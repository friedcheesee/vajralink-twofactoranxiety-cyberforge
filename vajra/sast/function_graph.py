"""
Inter-module / inter-procedural Function Graph + Root-Sink Propagation Analysis.

Builds a directed graph of *every* Java method in the target:
    nodes  = methods (Class.method@Lstart); kinds: entrypoint | service | helper
    edges  = resolved calls: "call" (same class / inherited), "di" (field-injected bean or interface impl),
             "static" (Type.method())
then overlays SAST findings on the nodes that enclose them.

Root-sink propagation (the mentor's ask):
    A vulnerability lives in exactly ONE root method/module. Every entrypoint (and every importing module) that
    can reach it through the call graph is a *propagated path*, not a separate vulnerability. For each
    (root method, CWE) we emit one cluster that lists the upstream callers, the importing modules, and how many
    per-endpoint alerts a graph-unaware tool would have raised (`alerts_without_graph`) vs ours (1).

The same graph drives:
    * SAST-guided DAST scoping (which routes can reach a flagged sink, with their CWE hints)
    * deeper call-graph reachability in the correlator (paths longer than 3 hops, interface dispatch)
    * reachability-aware SCA (is a vulnerable library symbol called from an entrypoint?)
"""
from __future__ import annotations

import os
import re
from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from vajra.models import CommonFinding, RouteEntry
from vajra.routemap.java_spring import extract_method_defs

JAVA_KEYWORDS = {
    "if", "for", "while", "catch", "switch", "synchronized", "new", "super", "this", "return", "throw", "else",
    "try", "equals", "assert", "instanceof", "case", "do", "finally",
}
_STRING_LIT = re.compile(r'"(?:\\.|[^"\\])*"')
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_CALL_RE = re.compile(r"(?<![\w.])(?:((?:[A-Za-z_]\w*\s*(?:\(\s*\)\s*)?\.\s*)*[A-Za-z_]\w*)\s*\.\s*)?([A-Za-z_]\w*)\s*\(")
_CLASS_DECL = re.compile(r"\b(?:public\s+|abstract\s+|final\s+)*(class|interface|enum)\s+([A-Za-z_]\w*)(?:\s+extends\s+([A-Za-z_][\w.<>]*))?(?:\s+implements\s+([^{]+))?")
_FIELD_DECL = re.compile(r"\b([A-Z][A-Za-z0-9_]*)(?:<[^>;{}()]*>)?\s+([a-z_][A-Za-z0-9_]*)\s*(?:[;=,)])")
_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+);", re.MULTILINE)
_SERVICE_ANN = re.compile(r"@(Service|Component|Repository|Configuration|Controller|RestController|\w*Controller)\b")


def _norm(p: Optional[str]) -> str:
    return (p or "").replace("\\", "/").strip("/").lower()


def canon_url(url: str) -> str:
    """Normalise a route pattern / URL path: single leading slash, no trailing slash. No application-specific
    prefix stripping - context-path handling lives in vajra/dast/urlutil.py (strip_prefix)."""
    return "/" + (url or "").strip("/")


def _strip_code(text: str) -> str:
    text = _BLOCK_COMMENT.sub(" ", text)
    text = _LINE_COMMENT.sub(" ", text)
    return _STRING_LIT.sub('""', text)


class _ClassRec:
    def __init__(self, name: str, file_path: str, kind: str):
        self.name = name
        self.file_path = file_path
        self.kind = kind
        self.extends: Optional[str] = None
        self.implements: List[str] = []
        self.annotation: Optional[str] = None
        self.var_types: Dict[str, str] = {}
        self.imports: Set[str] = set()
        self.methods: Dict[str, List[Tuple[int, int]]] = {}
        self.is_service = False


class FunctionGraph:
    def __init__(self) -> None:
        self.classes: Dict[str, _ClassRec] = {}
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.out: Dict[str, List[Tuple[str, str]]] = {}
        self.inc: Dict[str, List[Tuple[str, str]]] = {}
        self._by_file: Dict[str, List[Tuple[int, int, str]]] = {}
        self._file_lines: Dict[str, List[str]] = {}
        self._route_nodes: Dict[Tuple[str, str, int], str] = {}
        self.clusters: List[Dict[str, Any]] = []
        self.module_clusters: List[Dict[str, Any]] = []
        self.module_graph: Dict[str, Any] = {}
        self.stats: Dict[str, Any] = {}
        self._sink_nodes: Dict[str, List[Dict[str, Any]]] = {}

    # ------------------------------------------------------------------ build
    def _add_node(self, node_id: str, **attrs: Any) -> Dict[str, Any]:
        if node_id not in self.nodes:
            self.nodes[node_id] = {"id": node_id, **attrs}
            self.out.setdefault(node_id, [])
            self.inc.setdefault(node_id, [])
        return self.nodes[node_id]

    def _add_edge(self, src: str, dst: str, kind: str) -> None:
        if src == dst:
            return
        key = (src, dst)
        if key in self.edges:
            return
        self.edges[key] = {"src": src, "dst": dst, "kind": kind}
        self.out[src].append((dst, kind))
        self.inc[dst].append((src, kind))

    def innermost_node_at(self, file_path: str, line: int) -> Optional[str]:
        best: Optional[Tuple[int, str]] = None
        for s, e, nid in self._by_file.get(_norm(file_path), []):
            if s <= line <= e and (best is None or (e - s) < best[0]):
                best = (e - s, nid)
        return best[1] if best else None

    def node_source(self, node_id: Optional[str], max_lines: int = 30) -> str:
        """The real source text of a method node (its own body), for grounding AI reasoning in exactly the
        code that handler actually runs - as opposed to a shared sink's guard_snippet, which only reflects
        the few lines immediately before the sink inside whichever method directly encloses it.
        """
        if not node_id or node_id not in self.nodes:
            return ""
        n = self.nodes[node_id]
        lines = self._file_lines.get(_norm(n.get("file", "")))
        if not lines:
            return ""
        s, e = n.get("start", 1), n.get("end", 1)
        body = lines[max(0, s - 1):min(len(lines), e)]
        if len(body) > max_lines:
            body = body[:max_lines] + ["// ... (truncated)"]
        return "\n".join(body)

    def class_scope_node(self, file_path: str) -> Optional[str]:
        for c in self.classes.values():
            if _norm(c.file_path) == _norm(file_path):
                nid = f"{c.name}.<class-scope>"
                self._add_node(
                    nid, label=f"{c.name}.<class-scope>", cls=c.name, file=c.file_path, start=1, end=1,
                    kind="service" if c.is_service else "helper", routes=[], vulns=[], safe=[],
                )
                return nid
        return None

    # ----------------------------------------------------------------- queries
    def forward_path(self, src: str, dst: str, max_hops: int = 8) -> Optional[List[Tuple[str, str]]]:
        """Shortest call path src -> dst as [(node_id, edge_kind_into_node)], including src as first element."""
        if src == dst:
            return [(src, "entry")]
        prev: Dict[str, Tuple[str, str]] = {}
        dq: deque = deque([(src, 0)])
        seen = {src}
        while dq:
            cur, d = dq.popleft()
            if d >= max_hops:
                continue
            for nxt, kind in self.out.get(cur, []):
                if nxt in seen:
                    continue
                seen.add(nxt)
                prev[nxt] = (cur, kind)
                if nxt == dst:
                    path: List[Tuple[str, str]] = []
                    node = dst
                    while node != src:
                        p, k = prev[node]
                        path.append((node, k))
                        node = p
                    path.append((src, "entry"))
                    path.reverse()
                    return path
                dq.append((nxt, d + 1))
        return None

    def route_node(self, route: RouteEntry) -> Optional[str]:
        nid = self._route_nodes.get((_norm(route.file_path), route.handler_name, route.start_line))
        if nid:
            return nid
        return self.innermost_node_at(route.file_path, route.start_line)

    def describe_path(self, path: List[Tuple[str, str]]) -> str:
        parts: List[str] = []
        for i, (nid, kind) in enumerate(path):
            lab = self.nodes[nid]["label"]
            if i == 0:
                parts.append(lab)
            else:
                arrow = {"di": "-[@Service/DI]->", "static": "-[static]->"}.get(kind, "->")
                parts.append(f"{arrow} {lab}")
        return " ".join(parts)

    # ---------------------------------------------------------------- analysis
    def overlay_findings(self, active: Iterable[CommonFinding], suppressed: Iterable[CommonFinding] = ()) -> None:
        for f in active:
            self._attach(f, is_safe=False)
        for f in suppressed:
            self._attach(f, is_safe=True)

    def _attach(self, f: CommonFinding, is_safe: bool) -> None:
        if not f.file_path or not f.line or not str(f.file_path).endswith(".java"):
            return
        nid = self.innermost_node_at(f.file_path, f.line) or self.class_scope_node(f.file_path)
        if not nid:
            return
        entry = {
            "cwe": f.cwe,
            "raw_cwe": f.raw_cwe,
            "vuln_type": f.vuln_type,
            "line": f.line,
            "engines": list(f.engines),
            "snippet": (f.code_snippet or "")[:140],
            "code_snippet": f.code_snippet or "",
            "guard_snippet": f.guard_snippet or "",
            "function_name": f.function_name,
            "severity": f.severity,
            "reason": f.suppression_reason,
        }
        self.nodes[nid]["safe" if is_safe else "vulns"].append(entry)

    def analyze(self) -> None:
        clusters: List[Dict[str, Any]] = []
        entry_ids = [n for n, d in self.nodes.items() if d.get("routes")]
        for sink_id, sink in self.nodes.items():
            if not sink.get("vulns"):
                continue
            by_cwe: Dict[str, List[Dict[str, Any]]] = {}
            for v in sink["vulns"]:
                by_cwe.setdefault(v["cwe"], []).append(v)

            # reverse BFS: who can reach this sink method?
            nxt_hop: Dict[str, Tuple[str, str]] = {}
            depth: Dict[str, int] = {sink_id: 0}
            dq: deque = deque([sink_id])
            while dq:
                cur = dq.popleft()
                if depth[cur] >= 8:
                    continue
                for caller, kind in self.inc.get(cur, []):
                    if caller not in depth:
                        depth[caller] = depth[cur] + 1
                        nxt_hop[caller] = (cur, kind)
                        dq.append(caller)

            reached_entries = [e for e in entry_ids if e in depth]
            callers_modules: Set[str] = set()
            for nid in depth:
                if nid != sink_id and self.nodes[nid]["cls"] != sink["cls"]:
                    callers_modules.add(self.nodes[nid]["cls"])

            entry_records: List[Dict[str, Any]] = []
            for e in reached_entries:
                chain: List[Tuple[str, str]] = [(e, "entry")]
                cur = e
                while cur != sink_id:
                    n, k = nxt_hop[cur]
                    chain.append((n, k))
                    cur = n
                routes = [r for r in self.nodes[e]["routes"] if not r.get("secure")]
                entry_records.append(
                    {
                        "node_id": e,
                        "label": self.nodes[e]["label"],
                        "module": self.nodes[e]["cls"],
                        "routes": routes,
                        "hops": len(chain) - 1,
                        "cross_module": any(self.nodes[a]["cls"] != sink["cls"] for a, _ in chain[:-1]),
                        "path": self.describe_path(chain),
                        "path_nodes": [n for n, _ in chain],
                    }
                )
            entry_records.sort(key=lambda r: (r["hops"], r["label"]))
            route_urls: List[str] = []
            for r in entry_records:
                for rt in r["routes"]:
                    if rt["url"] not in route_urls:
                        route_urls.append(rt["url"])

            for cwe, vulns in by_cwe.items():
                engines = sorted({e for v in vulns for e in v["engines"]})
                clusters.append(
                    {
                        "id": f"{sink_id}|{cwe}",
                        "cwe": cwe,
                        "vuln_types": sorted({v["vuln_type"] for v in vulns}),
                        "root": {
                            "node_id": sink_id,
                            "module": sink["cls"],
                            "method": sink["label"],
                            "file": sink["file"],
                            "start": sink["start"],
                            "end": sink["end"],
                            "sink_lines": sorted({v["line"] for v in vulns}),
                            "snippets": [v["snippet"] for v in vulns][:3],
                        },
                        "engines": engines,
                        "entrypoints": entry_records,
                        "route_urls": route_urls,
                        "importing_modules": sorted(callers_modules),
                        "propagated_only_modules": sorted(
                            {r["module"] for r in entry_records if r["module"] != sink["cls"] and r["cross_module"]}
                        ),
                        "alerts_without_graph": max(1, len(route_urls)) if route_urls else 1,
                        "alerts_with_graph": 1,
                        "reachable_from_http": bool(route_urls),
                    }
                )
        clusters.sort(key=lambda c: (-c["alerts_without_graph"], c["cwe"], c["root"]["module"]))
        self.clusters = clusters
        self._build_module_clusters()
        self._build_module_graph()
        self._compute_stats()

    def _build_module_clusters(self) -> None:
        """One row per (root file, CWE) - the same granularity as the final deduplicated issue list."""
        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for c in self.clusters:
            key = (c["root"]["file"], c["cwe"])
            g = grouped.setdefault(
                key,
                {
                    "cwe": c["cwe"],
                    "root_module": c["root"]["module"],
                    "file": c["root"]["file"],
                    "root_methods": [],
                    "sink_lines": [],
                    "engines": set(),
                    "route_urls": [],
                    "entry_modules": set(),
                    "importing_modules": set(),
                    "max_hops": 0,
                },
            )
            g["root_methods"].append(c["root"]["method"])
            g["sink_lines"].extend(c["root"]["sink_lines"])
            g["engines"].update(c["engines"])
            g["importing_modules"].update(c["importing_modules"])
            for u in c["route_urls"]:
                if u not in g["route_urls"]:
                    g["route_urls"].append(u)
            for r in c["entrypoints"]:
                g["entry_modules"].add(r["module"])
                g["max_hops"] = max(g["max_hops"], r["hops"])
        rows = []
        for g in grouped.values():
            rows.append(
                {
                    "cwe": g["cwe"],
                    "root_module": g["root_module"],
                    "file": g["file"],
                    "root_methods": sorted(set(g["root_methods"])),
                    "sink_lines": sorted(set(g["sink_lines"])),
                    "engines": sorted(g["engines"]),
                    "route_urls": g["route_urls"],
                    "entry_modules": sorted(g["entry_modules"]),
                    "importing_modules": sorted(g["importing_modules"]),
                    "max_hops": g["max_hops"],
                    "alerts_without_graph": max(1, len(g["route_urls"])),
                    "alerts_with_graph": 1,
                }
            )
        rows.sort(key=lambda r: (-r["alerts_without_graph"], r["cwe"], r["root_module"]))
        self.module_clusters = rows

    def _build_module_graph(self) -> None:
        mod_edges: Dict[Tuple[str, str], int] = {}
        for (s, d), _e in self.edges.items():
            a, b = self.nodes[s]["cls"], self.nodes[d]["cls"]
            if a != b:
                mod_edges[(a, b)] = mod_edges.get((a, b), 0) + 1
        vuln_mods: Dict[str, Set[str]] = {}
        for n in self.nodes.values():
            if n.get("vulns"):
                vuln_mods.setdefault(n["cls"], set()).update(v["cwe"] for v in n["vulns"])
        root_clusters: Dict[str, int] = {}
        for c in self.clusters:
            root_clusters[c["root"]["module"]] = root_clusters.get(c["root"]["module"], 0) + 1
        importers: Dict[str, Set[str]] = {}
        exposure: Dict[str, Set[str]] = {}
        for c in self.clusters:
            for m in c["importing_modules"]:
                importers.setdefault(c["root"]["module"], set()).add(m)
        for root, ims in importers.items():
            for m in ims:
                exposure.setdefault(m, set()).update(vuln_mods.get(root, set()))
        involved = set(vuln_mods) | {m for ims in importers.values() for m in ims}
        modules = []
        for m in sorted(involved):
            own = sorted(vuln_mods.get(m, set()))
            exposed = sorted(exposure.get(m, set()) - set(own))
            role = "root" if own and importers.get(m) else ("vulnerable" if own else "importer")
            modules.append(
                {
                    "module": m,
                    "own_cwes": own,
                    "exposed_via_imports": exposed,
                    "imported_by": sorted(importers.get(m, set())),
                    "root_clusters": root_clusters.get(m, 0),
                    "role": role,
                }
            )
        self.module_graph = {
            "modules": modules,
            "edges": [
                {"src": a, "dst": b, "weight": w}
                for (a, b), w in sorted(mod_edges.items())
                if a in involved and b in involved
            ],
        }

    def _compute_stats(self) -> None:
        entry_count = sum(1 for n in self.nodes.values() if n.get("routes"))
        with_graph = len(self.module_clusters)
        without = sum(c["alerts_without_graph"] for c in self.module_clusters)
        cross = [c for c in self.module_clusters if c["importing_modules"]]
        self.stats = {
            "modules": len({n["cls"] for n in self.nodes.values()}),
            "methods": len(self.nodes),
            "call_edges": len(self.edges),
            "di_edges": sum(1 for e in self.edges.values() if e["kind"] == "di"),
            "static_edges": sum(1 for e in self.edges.values() if e["kind"] == "static"),
            "entrypoints": entry_count,
            "root_sink_methods": len(self.clusters),
            "root_sink_clusters": with_graph,
            "alerts_without_graph": without,
            "alerts_with_graph": with_graph,
            "alerts_collapsed": max(0, without - with_graph),
            "cross_module_clusters": len(cross),
            "reachable_from_http_clusters": sum(1 for c in self.module_clusters if c["route_urls"]),
        }

    # ----------------------------------------------------------- derived views
    def cluster_for(self, file_path: Optional[str], line: Optional[int], cwe: str) -> Optional[Dict[str, Any]]:
        if not file_path or not line:
            return None
        nid = self.innermost_node_at(file_path, line)
        if not nid:
            return None
        for c in self.clusters:
            if c["root"]["node_id"] == nid and c["cwe"] == cwe:
                return c
        return None

    def cluster_for_file(self, file_path: Optional[str], cwe: str) -> Optional[Dict[str, Any]]:
        best: Optional[Dict[str, Any]] = None
        for c in self.clusters:
            if _norm(c["root"]["file"]) == _norm(file_path) and c["cwe"] == cwe:
                if best is None or c["alerts_without_graph"] > best["alerts_without_graph"]:
                    best = c
        return best

    def targeted_route_plan(self, routes: List[RouteEntry], probeable_cwes: Optional[Set[str]] = None) -> Dict[str, Any]:
        """SAST -> DAST hand-off. Which (deduplicated) routes can reach a SAST-flagged sink?

        `probeable_cwes`: only CWEs an HTTP probe can actually confirm (crypto/secret/logic sinks cannot be
        proven by a request and stay Code-only). Returns {"routes": {"GET /X/LEVEL_1": {...}}, "stats": {...}}.
        """
        sink_cwes: Dict[str, Set[str]] = {}
        for c in self.clusters:
            sink_cwes.setdefault(c["root"]["node_id"], set()).add(c["cwe"])
        plan: Dict[str, Dict[str, Any]] = {}
        all_keys: Set[str] = set()
        for r in routes:
            if r.is_secure_variant:
                continue
            key = f"{r.http_method.upper()} {canon_url(r.url_pattern)}"
            all_keys.add(key)
            eid = self.route_node(r)
            if not eid:
                continue
            # This ROUTE's own handler source - e.g. getVulnerablePayloadLevel3()'s actual body. Several
            # levels of the same vulnerability class often delegate to one shared helper/sink, so the
            # sink's own guard_snippet (captured near the sink, inside the SHARED method) is identical for
            # every level and reflects only the common code - it is NOT where each level's distinguishing
            # filter lives. That filter lives in the level's own handler, which is what we read here.
            handler_src = self.node_source(eid)
            cwes: Set[str] = set()
            sinks = 0
            guard_ctx: List[Dict[str, Any]] = []
            seen = {eid}
            dq: deque = deque([(eid, 0)])
            while dq:
                cur, d = dq.popleft()
                if cur in sink_cwes:
                    hit = sink_cwes[cur] if probeable_cwes is None else (sink_cwes[cur] & probeable_cwes)
                    if hit:
                        cwes |= hit
                        sinks += 1
                        # Ground the AI bypass attempt in BOTH this exact finding's sink-level guard_snippet
                        # (the SAST engine's best-effort look-back from the sink line) AND this specific
                        # route's own handler body (the per-level filter, when the sink is shared).
                        sink_vulns = {v["cwe"]: v for v in self.nodes[cur].get("vulns", []) if v["cwe"] in hit}
                        for cwe_hit in hit:
                            v = sink_vulns.get(cwe_hit)
                            guard_ctx.append({
                                "cwe": cwe_hit,
                                "guard_snippet": (v or {}).get("guard_snippet", ""),
                                "code_snippet": (v or {}).get("code_snippet") or (v or {}).get("snippet", ""),
                                "handler_source": handler_src,
                                "handler_label": self.nodes[eid].get("label"),
                                "file": self.nodes[cur]["file"],
                                "line": (v or {}).get("line"),
                                "function_name": (v or {}).get("function_name") or self.nodes[cur].get("method"),
                            })
                if d >= 8:
                    continue
                for nxt, _k in self.out.get(cur, []):
                    if nxt not in seen:
                        seen.add(nxt)
                        dq.append((nxt, d + 1))
            if cwes:
                entry = plan.setdefault(key, {"cwes": set(), "sinks": 0, "params": list(r.params), "guard_context": []})
                entry["cwes"] |= cwes
                entry["sinks"] = max(entry["sinks"], sinks)
                seen_gc = {(g["file"], g["line"]) for g in entry["guard_context"]}
                for g in guard_ctx:
                    if (g["file"], g["line"]) not in seen_gc:
                        seen_gc.add((g["file"], g["line"]))
                        entry["guard_context"].append(g)
        for v in plan.values():
            v["cwes"] = sorted(v["cwes"])
        return {
            "routes": plan,
            "stats": {
                "unique_routes_total": len(all_keys),
                "targeted_routes": len(plan),
                "reduction_pct": round(100.0 * (1 - len(plan) / len(all_keys)), 1) if all_keys else 0.0,
            },
        }

    def view(self, cwe: Optional[str] = None, module: Optional[str] = None, max_clusters: int = 40) -> Dict[str, Any]:
        """Pruned subgraph: sink-bearing methods + every node on a path from an entrypoint to them."""
        chosen = [
            c for c in self.clusters
            if (not cwe or c["cwe"] == cwe) and (not module or module in (c["root"]["module"], *c["importing_modules"]))
        ]
        total_clusters = len(chosen)
        chosen = chosen[:max_clusters]
        keep: Set[str] = set()
        keep_edges: Set[Tuple[str, str]] = set()
        for c in chosen:
            keep.add(c["root"]["node_id"])
            for r in c["entrypoints"]:
                pn = r["path_nodes"]
                keep.update(pn)
                for a, b in zip(pn, pn[1:]):
                    keep_edges.add((a, b))
        # layer = hops-from-entrypoint (longest path position), computed on kept subgraph
        layer: Dict[str, int] = {n: 0 for n in keep}
        for _ in range(10):
            changed = False
            for a, b in keep_edges:
                if layer[b] < layer[a] + 1:
                    layer[b] = layer[a] + 1
                    changed = True
            if not changed:
                break
        cluster_by_root: Dict[str, List[str]] = {}
        for c in chosen:
            cluster_by_root.setdefault(c["root"]["node_id"], []).append(c["id"])
        nodes = []
        for nid in sorted(keep, key=lambda n: (layer[n], self.nodes[n]["label"])):
            n = self.nodes[nid]
            role = "entrypoint" if n.get("routes") else ("root-sink" if n.get("vulns") else n["kind"])
            nodes.append(
                {
                    "id": nid,
                    "label": n["label"],
                    "module": n["cls"],
                    "file": n["file"],
                    "start": n["start"],
                    "end": n["end"],
                    "role": role,
                    "layer": layer[nid],
                    "routes": [r for r in n.get("routes", [])][:6],
                    "route_count": len(n.get("routes", [])),
                    "vulns": n.get("vulns", []),
                    "cluster_ids": cluster_by_root.get(nid, []),
                    "is_root": nid in cluster_by_root,
                }
            )
        edges = [
            {"src": a, "dst": b, "kind": self.edges[(a, b)]["kind"]}
            for (a, b) in sorted(keep_edges)
            if (a, b) in self.edges
        ]
        return {"nodes": nodes, "edges": edges, "shown_clusters": len(chosen), "total_clusters": total_clusters}

    def to_dict(self, cwe: Optional[str] = None, module: Optional[str] = None, limit: int = 12) -> Dict[str, Any]:
        return {
            "stats": self.stats,
            "clusters": self.clusters,
            "module_clusters": self.module_clusters,
            "module_graph": self.module_graph,
            "view": self.view(cwe=cwe, module=module, max_clusters=limit),
        }


# ---------------------------------------------------------------------------- builder
def _parse_class_header(content: str, rel_path: str) -> Optional[_ClassRec]:
    stem = os.path.splitext(os.path.basename(rel_path))[0]
    chosen: Optional[re.Match] = None
    for m in _CLASS_DECL.finditer(content):
        if m.group(2) == stem:
            chosen = m
            break
    if chosen is None:
        chosen = _CLASS_DECL.search(content)
    if chosen is None:
        return None
    rec = _ClassRec(chosen.group(2), rel_path, chosen.group(1))
    if chosen.group(3):
        rec.extends = chosen.group(3).split(".")[-1].split("<")[0]
    if chosen.group(4):
        rec.implements = [x.strip().split("<")[0].split(".")[-1] for x in chosen.group(4).split(",") if x.strip()]
    header = content[: chosen.start()]
    ann = _SERVICE_ANN.findall(header[-600:])
    rec.annotation = ann[-1] if ann else None
    rec.is_service = bool(rec.annotation in {"Service", "Component", "Repository"} or re.search(r"(Service|Validator|Util|Utils|Helper|Provider|Manager)$", rec.name))
    return rec


def build_function_graph(
    source_root: str,
    routes: Optional[List[RouteEntry]] = None,
    active: Optional[Iterable[CommonFinding]] = None,
    suppressed: Optional[Iterable[CommonFinding]] = None,
) -> FunctionGraph:
    g = FunctionGraph()
    parsed: Dict[str, Tuple[_ClassRec, List[str], Dict[str, List[Tuple[int, int, List[str], List[str]]]]]] = {}

    for root, _dirs, files in os.walk(source_root):
        norm_root = root.replace("\\", "/")
        if "/src/test/" in norm_root or "/.git" in norm_root or "/build/" in norm_root:
            continue
        for fn in files:
            if not fn.endswith(".java"):
                continue
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, source_root).replace("\\", "/")
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            rec = _parse_class_header(content, rel)
            if rec is None or rec.name in g.classes:
                continue
            lines = content.splitlines()
            g._file_lines[_norm(rel)] = lines
            _, mdefs = extract_method_defs(lines)
            rec.imports = {m.split(".")[-1] for m in _IMPORT.findall(content)}
            code = _strip_code(content)
            for m in _FIELD_DECL.finditer(code):
                rec.var_types[m.group(2)] = m.group(1)
            g.classes[rec.name] = rec
            parsed[rec.name] = (rec, lines, mdefs)
            for name, overloads in mdefs.items():
                rec.methods[name] = [(s, e) for s, e, _, _ in overloads]

    # interface -> implementations
    impls: Dict[str, List[str]] = {}
    for rec in g.classes.values():
        for i in rec.implements + ([rec.extends] if rec.extends else []):
            impls.setdefault(i, []).append(rec.name)

    # nodes
    for cname, (rec, lines, mdefs) in parsed.items():
        for name, overloads in mdefs.items():
            for s, e, _calls, _params in overloads:
                nid = f"{cname}.{name}@L{s}"
                g._add_node(
                    nid, label=f"{cname}.{name}()", method=name, cls=cname, file=rec.file_path, start=s, end=e,
                    kind="service" if rec.is_service else "helper", routes=[], vulns=[], safe=[],
                )
                g._by_file.setdefault(_norm(rec.file_path), []).append((s, e, nid))

    # routes -> entrypoint nodes
    for r in routes or []:
        cands = [
            nid for (s, e, nid) in g._by_file.get(_norm(r.file_path), [])
            if g.nodes[nid]["method"] == r.handler_name and abs(s - r.start_line) <= 6
        ]
        nid = cands[0] if cands else g.innermost_node_at(r.file_path, r.start_line)
        if not nid:
            continue
        g._route_nodes[(_norm(r.file_path), r.handler_name, r.start_line)] = nid
        node = g.nodes[nid]
        node["kind"] = "entrypoint"
        url = canon_url(r.url_pattern)
        if not any(x["url"] == url and x["method"] == r.http_method.upper() for x in node["routes"]):
            node["routes"].append({"url": url, "method": r.http_method.upper(), "secure": r.is_secure_variant,
                                   "params": list(r.params)[:6]})

    def targets_for(cls: _ClassRec, qualifier: Optional[str], callee: str) -> List[Tuple[str, str]]:
        """Resolve a call to [(node_id, edge_kind)]."""
        results: List[Tuple[str, str]] = []

        def methods_in(cname: str, kind: str, seen: Optional[Set[str]] = None) -> None:
            seen = seen or set()
            if cname in seen or cname not in parsed:
                return
            seen.add(cname)
            rec = g.classes[cname]
            if callee in rec.methods:
                for s, _e in rec.methods[callee]:
                    results.append((f"{cname}.{callee}@L{s}", kind))
            elif rec.extends:
                methods_in(rec.extends, kind, seen)

        def dispatch(tname: str, kind: str) -> None:
            if tname in g.classes:
                methods_in(tname, kind)
            for impl in impls.get(tname, []):
                methods_in(impl, "di")

        if not qualifier or qualifier in ("this", "super"):
            methods_in(cls.name, "call")
            return results
        last = re.split(r"\s*\.\s*", qualifier.strip())[-1]
        last = re.sub(r"\(\s*\)$", "", last).strip()
        if last in cls.var_types:
            dispatch(cls.var_types[last], "di")
        elif last in g.classes and last[:1].isupper():
            dispatch(last, "static")
        return results

    # edges
    for cname, (rec, lines, mdefs) in parsed.items():
        for name, overloads in mdefs.items():
            for s, e, _calls, _params in overloads:
                src = f"{cname}.{name}@L{s}"
                body = _strip_code("\n".join(lines[s - 1:e]))
                for m in _CALL_RE.finditer(body):
                    callee = m.group(2)
                    if callee in JAVA_KEYWORDS or callee == name and not m.group(1):
                        if callee in JAVA_KEYWORDS:
                            continue
                    pre = body[max(0, m.start() - 4):m.start(2)]
                    if re.search(r"\bnew\s*$", pre):
                        continue
                    for dst, kind in targets_for(rec, m.group(1), callee):
                        g._add_edge(src, dst, kind)

    if active is not None:
        g.overlay_findings(active, suppressed or [])
        g.analyze()
    else:
        g._compute_stats()
    return g
