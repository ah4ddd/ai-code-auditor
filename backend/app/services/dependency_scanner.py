"""
Dependency Scanner Service
Parses common manifest files and queries OSV for known vulnerabilities.
"""
import os
import json
import re
from typing import List, Dict, Tuple
import requests


class DependencyScanner:
    """Lightweight dependency vulnerability scanner using OSV API."""

    OSV_API_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout_seconds: int = 10):
        self.timeout_seconds = timeout_seconds

    def scan_repository_manifests(self, repo_path: str) -> Dict:
        """
        Discover manifests and return detected dependencies and known vulns.
        Supported manifests: Python requirements.txt/poetry.lock, package.json/package-lock.json, Cargo.toml, go.mod.
        """
        manifests = self._discover_manifests(repo_path)
        dependencies = self._parse_manifests(manifests)
        vulnerabilities = self._query_osv_batch(dependencies)

        severity_weight = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
        total_risk = 0
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "LOW").upper()
            total_risk += severity_weight.get(sev, 1)

        return {
            "manifests": manifests,
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities,
            "dependency_risk_score": total_risk
        }

    def _discover_manifests(self, repo_path: str) -> List[str]:
        found = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", "env", "__pycache__", "target", "build", "dist"}]
            for fname in files:
                if fname in {"requirements.txt", "poetry.lock", "Pipfile.lock", "package.json", "package-lock.json", "Cargo.toml", "go.mod"}:
                    found.append(os.path.join(root, fname))
        return found

    def _parse_manifests(self, manifest_paths: List[str]) -> List[Dict]:
        deps: List[Dict] = []
        for path in manifest_paths:
            base = os.path.basename(path).lower()
            try:
                if base == "requirements.txt":
                    deps.extend(self._parse_requirements(path))
                elif base in {"package.json"}:
                    deps.extend(self._parse_package_json(path))
                elif base == "cargo.toml":
                    deps.extend(self._parse_cargo_toml(path))
                elif base == "go.mod":
                    deps.extend(self._parse_go_mod(path))
                # Others (locks) can be used later for exact versions
            except Exception:
                continue
        return deps

    def _parse_requirements(self, path: str) -> List[Dict]:
        deps = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # simple: pkg==ver or pkg>=ver
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=)?\s*([A-Za-z0-9_.\-]+)?", line)
                if m:
                    name, _op, ver = m.groups()
                    deps.append({"ecosystem": "PyPI", "name": name, "version": ver or "*"})
        return deps

    def _parse_package_json(self, path: str) -> List[Dict]:
        deps = []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, ver in (data.get(section) or {}).items():
                deps.append({"ecosystem": "npm", "name": name, "version": str(ver)})
        return deps

    def _parse_cargo_toml(self, path: str) -> List[Dict]:
        deps = []
        try:
            import tomllib  # py3.11+
            with open(path, "rb") as f:
                data = tomllib.load(f)
            for name, spec in (data.get("dependencies") or {}).items():
                if isinstance(spec, dict):
                    ver = spec.get("version") or "*"
                else:
                    ver = str(spec)
                deps.append({"ecosystem": "crates.io", "name": name, "version": ver})
        except Exception:
            pass
        return deps

    def _parse_go_mod(self, path: str) -> List[Dict]:
        deps = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("require ") or (line and not line.startswith("//") and not line.startswith("module ")):
                    parts = line.replace("require ", "").strip().split()
                    if len(parts) >= 2:
                        deps.append({"ecosystem": "Go", "name": parts[0], "version": parts[1]})
        return deps

    def _query_osv_batch(self, dependencies: List[Dict]) -> List[Dict]:
        vulns: List[Dict] = []
        for dep in dependencies:
            payload = {
                "package": {"name": dep["name"], "ecosystem": dep["ecosystem"]},
            }
            if dep.get("version") and dep["version"] != "*":
                payload["version"] = dep["version"]
            try:
                r = requests.post(self.OSV_API_URL, json=payload, timeout=self.timeout_seconds)
                if r.status_code == 200:
                    data = r.json()
                    for entry in data.get("vulns", []) or []:
                        severity = self._normalize_severity(entry)
                        vulns.append({
                            "id": entry.get("id"),
                            "summary": entry.get("summary"),
                            "severity": severity,
                            "affected_package": dep,
                            "references": entry.get("references", [])
                        })
            except Exception:
                continue
        return vulns

    def _normalize_severity(self, osv_entry: Dict) -> str:
        # Try to map CVSS scores to buckets
        severities = osv_entry.get("severity") or []
        score = None
        for s in severities:
            if s.get("type") in {"CVSS_V3", "CVSS_V2"}:
                try:
                    score = float((s.get("score") or "").split("/")[0])
                    break
                except Exception:
                    continue
        if score is None:
            return "LOW"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"


