"""
JAX-RS (Jersey / RESTEasy / Quarkus-style) route extractor.

Understands @ApplicationPath, class-level @Path + method-level @Path (templates like {id} or
{id: \\d+}), @GET/@POST/@PUT/@DELETE/@PATCH/@HEAD, @QueryParam, @PathParam, @FormParam (all become `params`),
@HeaderParam/@CookieParam (recorded in java_spring.ROUTE_INPUTS, not as params), and the unannotated entity
parameter of a body-carrying method (its DTO fields, read from the repo's own classes, become params and the
body is marked JSON). Every RouteEntry points at a real method span in a real file.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from vajra.models import RouteEntry
from vajra.routemap.java_spring import (
    ROUTE_INPUTS,
    _balanced_end,
    _eval_concat,
    _eval_values,
    _parse_ann_args,
    _split_param_decl,
    _split_top,
    collect_class_fields,
    extract_called_methods,
    extract_constants,
    extract_method_defs,
)

_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD")
_SKIP_DIRS = (".git", "target", "build", "node_modules")
_SIG_RE = re.compile(
    r"\s*(?:(?:public|protected|private|static|final|synchronized)\s+)*"
    r"(?:<[^>]*>\s*)?[\w<>\[\],\s\?\.]+?\s+([A-Za-z_]\w*)\s*\("
)
_TEMPLATE_VAR = re.compile(r"\{\s*([A-Za-z_]\w*)\s*(?::(?:[^{}]|\{[^{}]*\})*)?\}")


def _norm_template(path: str) -> str:
    return _TEMPLATE_VAR.sub(lambda m: "{" + m.group(1) + "}", path)


def _join(*parts: str) -> str:
    segs = [p.strip("/") for p in parts if p and p.strip("/")]
    return "/" + "/".join(segs)


def _java_files(source_root: str) -> List[str]:
    out: List[str] = []
    for cur, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        if "/src/test/" in cur.replace("\\", "/"):
            continue
        out.extend(os.path.join(cur, f) for f in files if f.endswith(".java"))
    return out


def extract_jaxrs_routes(source_root: str) -> List[RouteEntry]:
    texts: Dict[str, str] = {}
    for fp in _java_files(source_root):
        try:
            texts[fp] = open(fp, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
    jax = {fp: t for fp, t in texts.items() if re.search(r"\bjavax?\.ws\.rs|jakarta\.ws\.rs|@Path\b", t) and "@Path" in t}
    if not jax:
        return []

    class_fields: Dict[str, List[str]] = {}
    for t in texts.values():
        for k, v in collect_class_fields(t).items():
            class_fields.setdefault(k, v)

    app_path = ""
    for t in texts.values():
        am = re.search(r"@ApplicationPath\s*\(\s*([^)]*)\)", t)
        if am:
            vals = _eval_values(am.group(1).strip(), extract_constants(t))
            if vals:
                app_path = vals[0]
                break

    routes: List[RouteEntry] = []
    for fp, content in jax.items():
        rel = os.path.relpath(fp, source_root).replace("\\", "/")
        lines = content.splitlines()
        consts = extract_constants(content)
        cls = re.search(r"(?:public\s+)?(?:abstract\s+)?(?:class|interface)\s+(\w+)", content)
        class_name = cls.group(1) if cls else Path(fp).stem
        cls_pos = cls.start() if cls else 0
        base = ""
        pm = None
        for pm in re.finditer(r"@Path\s*\(", content[:cls_pos]):
            pass
        if pm is not None:
            end = _balanced_end(content, pm.end() - 1)
            vals = _eval_values(content[pm.end():end].strip(), consts)
            base = vals[0] if vals else ""
        _, method_defs = extract_method_defs(lines, consts)

        # verb annotations anywhere after the class header
        for vm in re.finditer(r"@(" + "|".join(_VERBS) + r")\b", content[cls_pos:]):
            verb = vm.group(1)
            v_start = cls_pos + vm.start()
            pos = cls_pos + vm.end()
            # collect annotations between the verb and the signature (@Path, @Produces, ...) - also those
            # stacked above the verb annotation, back to the previous statement boundary
            above = content[max(0, v_start - 400):v_start]
            above = above[max(above.rfind(";"), above.rfind("}"), above.rfind("{")) + 1:]
            sub = ""
            between_start = pos
            while True:
                am = re.match(r"\s*@([\w.]+)", content[pos:])
                if not am:
                    break
                pos += am.end()
                if re.match(r"\s*\(", content[pos:pos + 20]):
                    end = _balanced_end(content, content.index("(", pos))
                    if end < 0:
                        break
                    pos = end + 1
            ann_zone = above + content[between_start:pos]
            for pam in re.finditer(r"@Path\s*\(", ann_zone):
                end = _balanced_end(ann_zone, pam.end() - 1)
                vals = _eval_values(ann_zone[pam.end():end].strip(), consts)
                if vals:
                    sub = vals[0]
            sm = _SIG_RE.match(content, pos)
            if not sm or re.search(r"\b(class|interface|enum|new)\b", content[pos:sm.end()]):
                continue
            handler = sm.group(1)
            p_open = sm.end() - 1
            p_end = _balanced_end(content, p_open)
            if p_end < 0 or not re.match(r"\s*(?:throws\s+[\w,.\s]+)?\s*\{", content[p_end + 1:]):
                continue
            handler_line = content.count("\n", 0, sm.start(1)) + 1
            span = (handler_line, min(handler_line + 35, len(lines)))
            for ms, me, _, _ in method_defs.get(handler, []):
                if abs(ms - handler_line) <= 4:
                    span = (ms, me)
                    break
            body = "\n".join(lines[span[0] - 1:span[1]])

            params: List[str] = []
            side: Dict[str, object] = {}

            def _add(n: str) -> None:
                if n and n not in params:
                    params.append(n)

            for decl in _split_top(content[p_open + 1:p_end]):
                anns, ptype, var = _split_param_decl(decl)
                if not var:
                    continue
                names = {n: a for n, a in anns}
                picked = False
                for ann in ("QueryParam", "PathParam", "FormParam"):
                    if ann in names:
                        v = _eval_concat(names[ann].strip(), consts)
                        _add(v if v is not None else var)
                        picked = True
                for ann, key in (("HeaderParam", "header"), ("CookieParam", "cookie")):
                    if ann in names:
                        v = _eval_concat(names[ann].strip(), consts)
                        side.setdefault(key, []).append(v if v is not None else var)  # type: ignore[union-attr]
                        picked = True
                if not picked and not names and verb in ("POST", "PUT", "PATCH"):
                    base_type = re.sub(r"<.*$", "", ptype).split(".")[-1]
                    for f in class_fields.get(base_type, []):
                        _add(f)
                    if base_type in class_fields:
                        side["body"] = "json"

            full = _norm_template(_join(app_path, base, sub))
            ROUTE_INPUTS[(rel, span[0])] = side
            routes.append(RouteEntry(
                http_method=verb, url_pattern=full, handler_name=handler, class_name=class_name,
                file_path=rel, start_line=span[0], end_line=span[1], params=params,
                called_helpers=extract_called_methods(body),
            ))
    return routes
