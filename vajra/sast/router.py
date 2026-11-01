"""
Adaptive Scanner Router & Project Fingerprinter (FR-1).
Detects languages, frameworks, build systems, keystores, and compiled bytecode.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class ProjectProfile:
    source_root: str
    languages: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    build_systems: List[str] = field(default_factory=list)
    has_bytecode: bool = False
    has_keystores: bool = False
    properties_files: List[str] = field(default_factory=list)
    total_files_scanned: int = 0


def detect_project_profile(source_root: str) -> ProjectProfile:
    languages = set()
    frameworks = set()
    build_systems = set()
    has_bytecode = False
    has_keystores = False
    properties_files = []
    total_files = 0

    for root, _, files in os.walk(source_root):
        for f in files:
            total_files += 1
            ext = os.path.splitext(f)[1].lower()
            rel = os.path.relpath(os.path.join(root, f), source_root)

            if ext == ".java":
                languages.add("java")
            elif ext == ".py":
                languages.add("python")
            elif ext in {".js", ".ts", ".jsx", ".tsx"}:
                languages.add("javascript")
            elif ext == ".class":
                has_bytecode = True
            elif ext in {".p12", ".pem", ".key", ".jks", ".pkcs12"}:
                has_keystores = True
            elif ext == ".properties" or f.endswith(".env") or f.endswith(".yaml") or f.endswith(".yml"):
                properties_files.append(rel)

            if f in {"build.gradle", "build.gradle.kts"}:
                build_systems.add("gradle")
            elif f == "pom.xml":
                build_systems.add("maven")
            elif f == "package.json":
                build_systems.add("npm")
            elif f in {"pyproject.toml", "requirements.txt", "Pipfile"}:
                build_systems.add("pip")

    # Inspect frameworks from files
    if "java" in languages:
        frameworks.add("spring-boot")
    if "python" in languages:
        frameworks.add("python-web")

    return ProjectProfile(
        source_root=source_root,
        languages=sorted(list(languages)),
        frameworks=sorted(list(frameworks)),
        build_systems=sorted(list(build_systems)),
        has_bytecode=has_bytecode,
        has_keystores=has_keystores,
        properties_files=properties_files,
        total_files_scanned=total_files,
    )
