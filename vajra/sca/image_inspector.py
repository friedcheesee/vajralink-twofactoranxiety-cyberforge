"""
Container image inspector: builds the *real* SBOM of a locally available Docker image.

 * Java libraries: copies /app/libs out of the image and reads META-INF/maven/<group>/<artifact>/pom.properties from each
   jar, so group / artifact / version are the resolved ones (not a curated table). Falls back to the file name.
 * OS packages: dpkg-query inside the image.
 * Image facts: base OS, user the container runs as (root?), size, created date.

Requires a running Docker daemon and the image to be present locally; returns {"available": False, ...} otherwise.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from typing import Any, Dict, List, Optional


def _run(cmd: List[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def docker_available() -> bool:
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        return _run([exe, "info", "--format", "{{.ServerVersion}}"], timeout=20).returncode == 0
    except Exception:
        return False


def image_present(image: str) -> bool:
    try:
        return _run(["docker", "image", "inspect", image], timeout=20).returncode == 0
    except Exception:
        return False


def _read_pom_properties(jar_path: str) -> Optional[Dict[str, str]]:
    try:
        with zipfile.ZipFile(jar_path) as z:
            for n in z.namelist():
                if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
                    props = {}
                    for ln in z.read(n).decode("utf-8", "ignore").splitlines():
                        if "=" in ln and not ln.startswith("#"):
                            k, v = ln.split("=", 1)
                            props[k.strip()] = v.strip()
                    if props.get("groupId") and props.get("artifactId") and props.get("version"):
                        return props
    except Exception:
        pass
    return None


def inspect_image(image: str, libs_path: str = "/app/libs") -> Dict[str, Any]:
    if not docker_available():
        return {"available": False, "image": image, "reason": "Docker daemon not reachable"}
    if not image_present(image):
        return {"available": False, "image": image, "reason": f"image '{image}' is not present locally (docker pull it first)"}

    out: Dict[str, Any] = {"available": True, "image": image, "jars": [], "os_packages": [], "facts": {}}
    try:
        meta = _run(["docker", "image", "inspect", image, "--format", "{{.Size}}|{{.Created}}|{{.Architecture}}|{{.Config.User}}"], 30)
        if meta.returncode == 0:
            size, created, arch, cfg_user = (meta.stdout.strip().split("|") + ["", "", "", ""])[:4]
            out["facts"].update({"size_mb": round(int(size) / 1e6, 1) if size.isdigit() else None, "created": created, "arch": arch, "config_user": cfg_user or None})
        probe = _run(
            ["docker", "run", "--rm", "--entrypoint", "sh", image, "-c",
             "echo '##OS'; grep -E '^(PRETTY_NAME|VERSION_ID|ID)=' /etc/os-release; echo '##UID'; id -u; "
             "echo '##DPKG'; dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n' 2>/dev/null"],
            120,
        )
        section = None
        for ln in probe.stdout.splitlines():
            if ln.startswith("##"):
                section = ln[2:]
                continue
            if section == "OS" and "=" in ln:
                k, v = ln.split("=", 1)
                out["facts"]["os_" + k.lower()] = v.strip('"')
            elif section == "UID" and ln.strip().isdigit():
                out["facts"]["runs_as_uid"] = int(ln.strip())
            elif section == "DPKG" and "\t" in ln:
                name, ver, arch = (ln.split("\t") + ["", ""])[:3]
                out["os_packages"].append({"name": name, "version": ver, "arch": arch})
    except Exception as exc:
        out["facts"]["probe_error"] = f"{type(exc).__name__}: {exc}"[:160]

    # copy the jars out and read their real Maven coordinates
    tmp = tempfile.mkdtemp(prefix="vajra_img_")
    cid = None
    try:
        created = _run(["docker", "create", image], 60)
        cid = created.stdout.strip()
        if created.returncode == 0 and cid:
            cp = _run(["docker", "cp", f"{cid}:{libs_path}", os.path.join(tmp, "libs")], 180)
            libs_dir = os.path.join(tmp, "libs")
            if cp.returncode == 0 and os.path.isdir(libs_dir):
                for f in sorted(os.listdir(libs_dir)):
                    if not f.endswith(".jar"):
                        continue
                    props = _read_pom_properties(os.path.join(libs_dir, f))
                    if props:
                        out["jars"].append({"file": f, "group": props["groupId"], "artifact": props["artifactId"], "version": props["version"], "source": "pom.properties"})
                    else:
                        m = re.match(r"^(.*?)-(\d[\w.\-]*)\.jar$", f)
                        if m:
                            out["jars"].append({"file": f, "group": None, "artifact": m.group(1), "version": m.group(2), "source": "file name"})
            else:
                out["facts"]["libs_error"] = (cp.stderr or "copy failed")[:160]
    except Exception as exc:
        out["facts"]["libs_error"] = f"{type(exc).__name__}: {exc}"[:160]
    finally:
        if cid:
            try:
                _run(["docker", "rm", "-f", cid], 30)
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
    return out
