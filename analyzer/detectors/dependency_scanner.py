import json
import re
from pathlib import Path
from analyzer.models import Finding, DetectorResult, Severity

KNOWN_MALICIOUS = {
    "ctx", "rectify", "smb", "acquirer", "loglib-modules",
    "httpx-async", "pyshark-updated", "aiohttp-requests",
    "request-plus", "colourama", "bitcoinlib-dev",
    "setup-tools", "python-utils-plus", "system-address",
}

POPULAR_PACKAGES = [
    "numpy", "pandas", "requests", "flask", "django",
    "scipy", "matplotlib", "tensorflow", "torch", "sklearn",
    "fastapi", "sqlalchemy", "pydantic", "celery", "redis",
    "boto3", "paramiko", "cryptography", "pillow", "pytest",
    "express", "lodash", "axios", "react", "webpack",
    "typescript", "eslint", "prettier", "jest", "mocha",
    "mongoose", "sequelize", "passport", "helmet", "cors",
]

TYPOSQUAT_THRESHOLD = 2

SUSPICIOUS_NAME_PATTERNS = [
    re.compile(r"^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+$"),
    re.compile(r"\d{5,}"),
    re.compile(r"^.{50,}$"),
    re.compile(r"\."),
]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    matrix = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        matrix[i][0] = i
    for j in range(len(b) + 1):
        matrix[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost,
            )
    return matrix[len(a)][len(b)]


def _extract_pip_package_name(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    if line.startswith("git+") or line.startswith("http://") or line.startswith("https://"):
        return None
    line = line.split("#")[0].strip()
    if not line:
        return None
    line = re.sub(r"\[.*?\]", "", line)
    pkg = re.split(r"[>=<!;,\s]", line)[0].strip().lower()
    return pkg if pkg else None


def _is_pinned_pip(line: str) -> bool:
    return bool(re.search(r"[>=<!]", line.split("#")[0]))


def _check_suspicious_name(pkg: str, file_path: str, line_num: int) -> Finding | None:
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern.search(pkg):
            return Finding(
                detector="dependency_scanner",
                severity=Severity.MEDIUM,
                rule_id="DEP_008",
                description=f"Suspicious package name pattern: '{pkg}'",
                file_path=file_path,
                line_number=line_num,
                match=pkg,
            )
    return None


def _check_requirements_txt(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        if line.startswith("git+") or (
            (line.startswith("http://") or line.startswith("https://"))
            and not line.startswith("#")
        ):
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.HIGH,
                rule_id="DEP_005",
                description="Direct URL/git install bypasses PyPI security checks",
                file_path=relative,
                line_number=line_num,
                match=line[:80],
            ))
            continue

        if "--index-url" in line or "--extra-index-url" in line:
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.HIGH,
                rule_id="DEP_006",
                description="Custom PyPI index URL — packages may not be from official PyPI",
                file_path=relative,
                line_number=line_num,
                match=line[:80],
            ))
            continue

        pkg = _extract_pip_package_name(raw_line)
        if not pkg:
            continue

        if pkg in KNOWN_MALICIOUS:
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.CRITICAL,
                rule_id="DEP_001",
                description=f"Known malicious package: '{pkg}'",
                file_path=relative,
                line_number=line_num,
                match=pkg,
            ))
            continue

        if not _is_pinned_pip(raw_line):
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.LOW,
                rule_id="DEP_003",
                description=f"Unpinned dependency '{pkg}' — version not locked",
                file_path=relative,
                line_number=line_num,
                match=pkg,
            ))

        for popular in POPULAR_PACKAGES:
            if pkg == popular:
                break
            distance = _levenshtein(pkg, popular)
            if 0 < distance <= TYPOSQUAT_THRESHOLD:
                findings.append(Finding(
                    detector="dependency_scanner",
                    severity=Severity.HIGH,
                    rule_id="DEP_002",
                    description=f"Package '{pkg}' is suspiciously similar to '{popular}' (edit distance {distance})",
                    file_path=relative,
                    line_number=line_num,
                    match=pkg,
                ))
                break

        suspicious = _check_suspicious_name(pkg, relative, line_num)
        if suspicious:
            findings.append(suspicious)

    return findings


def _check_package_json(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
        data = json.loads(content)
    except (OSError, PermissionError, json.JSONDecodeError):
        return findings

    if not isinstance(data, dict):
        return findings

    all_deps = {
        **data.get("dependencies", {}),
        **data.get("devDependencies", {}),
        **data.get("optionalDependencies", {}),
    }

    for line_num, (pkg, version) in enumerate(all_deps.items(), start=1):
        pkg_lower = re.sub(r"^@[^/]+/", "", pkg).lower()

        if pkg_lower in KNOWN_MALICIOUS:
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.CRITICAL,
                rule_id="DEP_001",
                description=f"Known malicious package: '{pkg}'",
                file_path=relative,
                line_number=line_num,
                match=pkg,
            ))
            continue

        if str(version).strip() in ("*", "latest", ""):
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.MEDIUM,
                rule_id="DEP_004",
                description=f"Wildcard version for '{pkg}' — unpredictable installs",
                file_path=relative,
                line_number=line_num,
                match=f"{pkg}@{version}",
            ))

        for popular in POPULAR_PACKAGES:
            if pkg_lower == popular:
                break
            distance = _levenshtein(pkg_lower, popular)
            if 0 < distance <= TYPOSQUAT_THRESHOLD:
                findings.append(Finding(
                    detector="dependency_scanner",
                    severity=Severity.HIGH,
                    rule_id="DEP_002",
                    description=f"Package '{pkg}' is suspiciously similar to '{popular}' (edit distance {distance})",
                    file_path=relative,
                    line_number=line_num,
                    match=pkg,
                ))
                break

    return findings


def _check_setup_py(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    matches = re.findall(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
    for match in matches:
        packages = re.findall(r"['\"]([^'\"]+)['\"]", match)
        for pkg_raw in packages:
            pkg = re.split(r"[>=<!;\[]", pkg_raw)[0].strip().lower()
            if not pkg:
                continue
            if pkg in KNOWN_MALICIOUS:
                findings.append(Finding(
                    detector="dependency_scanner",
                    severity=Severity.CRITICAL,
                    rule_id="DEP_001",
                    description=f"Known malicious package in setup.py: '{pkg}'",
                    file_path=relative,
                    line_number=0,
                    match=pkg,
                ))
            for popular in POPULAR_PACKAGES:
                if pkg == popular:
                    break
                distance = _levenshtein(pkg, popular)
                if 0 < distance <= TYPOSQUAT_THRESHOLD:
                    findings.append(Finding(
                        detector="dependency_scanner",
                        severity=Severity.HIGH,
                        rule_id="DEP_002",
                        description=f"Package '{pkg}' in setup.py is suspiciously similar to '{popular}'",
                        file_path=relative,
                        line_number=0,
                        match=pkg,
                    ))
                    break

    return findings


def _check_pyproject_toml(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    in_deps_section = False
    seen = set()

    for line in content.splitlines():
        stripped = line.strip()

        if stripped in (
            "[tool.poetry.dependencies]",
            "[tool.poetry.dev-dependencies]",
            "[project.dependencies]",
            "[project.optional-dependencies]",
            "[dependencies]",
        ):
            in_deps_section = True
            continue

        if stripped.startswith("[") and stripped.endswith("]") and in_deps_section:
            in_deps_section = False
            continue

        if not in_deps_section:
            continue

        match = re.match(r'^([a-zA-Z0-9_\-]+)\s*=', stripped)
        if not match:
            continue

        pkg = match.group(1).strip().lower()
        if not pkg or pkg in seen:
            continue
        seen.add(pkg)

        if pkg in KNOWN_MALICIOUS:
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.CRITICAL,
                rule_id="DEP_001",
                description=f"Known malicious package in pyproject.toml: '{pkg}'",
                file_path=relative,
                line_number=0,
                match=pkg,
            ))

        for popular in POPULAR_PACKAGES:
            if pkg == popular:
                break
            distance = _levenshtein(pkg, popular)
            if 0 < distance <= TYPOSQUAT_THRESHOLD:
                findings.append(Finding(
                    detector="dependency_scanner",
                    severity=Severity.HIGH,
                    rule_id="DEP_002",
                    description=f"Package '{pkg}' in pyproject.toml is suspiciously similar to '{popular}'",
                    file_path=relative,
                    line_number=0,
                    match=pkg,
                ))
                break

    return findings


def _check_pipfile(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    packages = re.findall(r'^([a-zA-Z0-9_\-]+)\s*=', content, re.MULTILINE)
    for pkg_raw in packages:
        pkg = pkg_raw.strip().lower()
        if not pkg or pkg in ("source", "requires", "packages", "dev-packages"):
            continue
        if pkg in KNOWN_MALICIOUS:
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.CRITICAL,
                rule_id="DEP_001",
                description=f"Known malicious package in Pipfile: '{pkg}'",
                file_path=relative,
                line_number=0,
                match=pkg,
            ))
        for popular in POPULAR_PACKAGES:
            if pkg == popular:
                break
            distance = _levenshtein(pkg, popular)
            if 0 < distance <= TYPOSQUAT_THRESHOLD:
                findings.append(Finding(
                    detector="dependency_scanner",
                    severity=Severity.HIGH,
                    rule_id="DEP_002",
                    description=f"Package '{pkg}' in Pipfile is suspiciously similar to '{popular}'",
                    file_path=relative,
                    line_number=0,
                    match=pkg,
                ))
                break

    return findings


def _check_conda_env(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    in_deps = False
    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped == "dependencies:":
            in_deps = True
            continue
        if in_deps and stripped.startswith("-"):
            pkg = stripped.lstrip("- ").split("=")[0].strip().lower()
            if not pkg or pkg.startswith("#"):
                continue
            if pkg in KNOWN_MALICIOUS:
                findings.append(Finding(
                    detector="dependency_scanner",
                    severity=Severity.CRITICAL,
                    rule_id="DEP_001",
                    description=f"Known malicious package in conda environment: '{pkg}'",
                    file_path=relative,
                    line_number=line_num,
                    match=pkg,
                ))
            for popular in POPULAR_PACKAGES:
                if pkg == popular:
                    break
                distance = _levenshtein(pkg, popular)
                if 0 < distance <= TYPOSQUAT_THRESHOLD:
                    findings.append(Finding(
                        detector="dependency_scanner",
                        severity=Severity.HIGH,
                        rule_id="DEP_002",
                        description=f"Package '{pkg}' in conda environment is suspiciously similar to '{popular}'",
                        file_path=relative,
                        line_number=line_num,
                        match=pkg,
                    ))
                    break

    return findings


def _check_pip_in_code(file_path: Path, root: Path) -> list[Finding]:
    findings = []
    relative = str(file_path.relative_to(root))

    try:
        content = file_path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    for line_num, line in enumerate(content.splitlines(), start=1):
        if re.search(r'(subprocess|os\.system|os\.popen).*["\']pip["\']|pip\s+install', line):
            findings.append(Finding(
                detector="dependency_scanner",
                severity=Severity.HIGH,
                rule_id="DEP_007",
                description="Runtime pip install — installs packages dynamically at execution time",
                file_path=relative,
                line_number=line_num,
                match=line.strip()[:80],
            ))

    return findings


def run(skill_root: Path) -> DetectorResult:
    findings = []

    for file_path in skill_root.rglob("requirements.txt"):
        findings.extend(_check_requirements_txt(file_path, skill_root))

    for file_path in skill_root.rglob("package.json"):
        if "node_modules" not in str(file_path):
            findings.extend(_check_package_json(file_path, skill_root))

    for file_path in skill_root.rglob("setup.py"):
        findings.extend(_check_setup_py(file_path, skill_root))

    for file_path in skill_root.rglob("pyproject.toml"):
        findings.extend(_check_pyproject_toml(file_path, skill_root))

    for file_path in skill_root.rglob("Pipfile"):
        findings.extend(_check_pipfile(file_path, skill_root))

    for file_path in skill_root.rglob("environment.yml"):
        findings.extend(_check_conda_env(file_path, skill_root))

    for file_path in skill_root.rglob("*.py"):
        findings.extend(_check_pip_in_code(file_path, skill_root))

    for file_path in skill_root.rglob("*.js"):
        findings.extend(_check_pip_in_code(file_path, skill_root))

    return DetectorResult(
        detector="dependency_scanner",
        passed=len(findings) == 0,
        findings=findings,
    )
