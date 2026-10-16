"""Distribution-aware, read-only package vulnerability lookups."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from vulpnix.cvss import calculate_cvss
from vulpnix.findings import CVEAssessment, CVSSScore, Finding, FindingStatus
from vulpnix.models.packages import (
    InstalledPackage,
    PackageAudit,
    PackageInventory,
)


ARCH_TRACKER_URL = "https://security.archlinux.org/all.json"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
USER_AGENT = "Vulpnix/0.1.0"
MAX_RESPONSE_BYTES = 24 * 1024 * 1024
BATCH_SIZE = 100
MAX_OSV_PACKAGES = 2500
MAX_ADVISORY_DETAILS = 100

NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_BATCH_SIZE = 100
NVD_CACHE_TTL_SECONDS = 6 * 60 * 60
_NVD_CVSS_CACHE: dict[str, tuple[float, tuple[CVSSScore, ...]]] = {}

SEVERITY_IMPACT = {
    "LOW": 2,
    "MEDIUM": 3,
    "MODERATE": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _http_json(url: str, payload: dict[str, Any] | None = None, *, timeout: int = 15):
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    with urlopen(request, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)

    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Advisory response exceeded the configured size limit.")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, (dict, list)):
        raise ValueError("Advisory response has an unsupported JSON shape.")
    return parsed


def _osv_ecosystem(inventory: PackageInventory) -> str | None:
    """Map only distributions whose OSV ecosystem and release are identifiable."""
    distro = inventory.distribution_id.strip().lower()
    release = inventory.release.strip()
    pretty_name = inventory.distribution_name.strip()

    if distro == "debian" and release:
        major = release.split(".", 1)[0]
        if major.isdigit():
            return f"Debian:{major}"
        if release.lower() in {"sid", "unstable"}:
            return "Debian:sid"

    if distro == "ubuntu" and re.fullmatch(r"\d{2}\.\d{2}(?:\.\d+)?", release):
        major, minor = release.split(".")[:2]
        normalized_release = f"{major}.{minor}"
        year = int(major)
        is_lts = minor == "04" and year % 2 == 0
        suffix = ":LTS" if is_lts else ""
        return f"Ubuntu:{normalized_release}{suffix}"

    if distro == "alpine" and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", release):
        major, minor = release.split(".")[:2]
        return f"Alpine:v{major}.{minor}"

    if distro == "almalinux" and release:
        major = release.split(".", 1)[0]
        return f"AlmaLinux:{major}" if major.isdigit() else None

    if distro == "rocky" and release:
        major = release.split(".", 1)[0]
        return f"Rocky Linux:{major}" if major.isdigit() else None

    if distro in {"azurelinux", "cbl-mariner", "mariner"}:
        if re.fullmatch(r"\d+(?:\.\d+)?", release):
            return f"Azure Linux:{release}"

    if distro == "mageia" and re.fullmatch(r"\d+(?:\.\d+)?", release):
        major = release.split(".", 1)[0]
        return f"Mageia:{major}"

    if distro in {"opensuse", "opensuse-leap", "opensuse-tumbleweed"}:
        if pretty_name.lower().startswith("opensuse "):
            if distro == "opensuse-tumbleweed" or (release and release in pretty_name):
                # OSV's openSUSE release suffix is the marketing name from
                # PRETTY_NAME; inventory uses it when present.
                return f"openSUSE:{pretty_name}"

    if distro in {"suse", "sles"} and pretty_name.lower().startswith("suse "):
        release_in_name = bool(release and release in pretty_name)
        version_parts = release.split(".", 1)
        service_pack_in_name = (
            len(version_parts) == 2
            and version_parts[0].isdigit()
            and version_parts[1].isdigit()
            and re.search(
                rf"\b{re.escape(version_parts[0])}\s+SP{re.escape(version_parts[1])}\b",
                pretty_name,
                re.IGNORECASE,
            ) is not None
        )
        if release_in_name or service_pack_in_name:
            return f"SUSE:{pretty_name}"

    # Do not guess product-stream CPEs for Red Hat-based distributions.
    # They are required for an accurate Red Hat OSV ecosystem mapping.
    return None

def _version_compare_arch(installed: str, fixed: str, *, which=None, runner=None) -> int | None:
    """Return vercmp(installed, fixed); None means comparison was not reliable."""
    if which is None:
        which = shutil.which
    if runner is None:
        runner = subprocess.run

    executable = which("vercmp")
    if not executable:
        return None

    try:
        result = runner(
            [executable, installed, fixed],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            shell=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if result.returncode != 0:
            return None
        return int((result.stdout or "").strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _clean(value: object, limit: int = 400) -> str:
    text = str(value or "")
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    return text[:limit]


def _risk_profile(severity: str | None, cvss_vector: str | None, *, confirmed: bool):
    """Return qualitative risk fields only when the source supports a profile."""
    if not confirmed:
        return None, None, None

    # CVSS v3 vector metrics inform qualitative dimensions; these are Vulpnix
    # ordinal factors, not a recalculated CVSS base score.
    if cvss_vector and cvss_vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        metrics = {}
        for field in cvss_vector.split("/")[1:]:
            if ":" in field:
                key, value = field.split(":", 1)
                metrics[key] = value

        if all(key in metrics for key in ("AV", "AC", "PR", "UI", "C", "I", "A")):
            impacts = [metrics[key] for key in ("C", "I", "A")]
            high_count = impacts.count("H")
            low_count = impacts.count("L")
            if high_count == 3:
                impact = 5
            elif high_count >= 2:
                impact = 4
            elif high_count == 1:
                impact = 3
            elif low_count >= 2:
                impact = 3
            elif low_count == 1:
                impact = 2
            else:
                impact = 1

            probability = {"N": 4, "A": 3, "L": 2, "P": 1}.get(metrics["AV"], 2)
            probability -= {"L": 0, "H": 1}.get(metrics["AC"], 0)
            probability -= {"N": 0, "L": 1, "H": 2}.get(metrics["PR"], 0)
            probability -= {"N": 0, "R": 1}.get(metrics["UI"], 0)
            probability = min(5, max(1, probability))
            rationale = (
                f"Impact {impact} is a qualitative mapping of the advisory's CVSS v3 "
                f"confidentiality/integrity/availability metrics. Probability {probability} "
                "is an ordinal proxy based on attack vector, complexity, privileges and "
                "user interaction; it is not statistical and does not account for this "
                "host's full exposure or configuration."
            )
            return impact, probability, rationale

    normalized = (severity or "").upper()
    impact = SEVERITY_IMPACT.get(normalized)
    if impact is None:
        return None, None, None

    probability = 3
    rationale = (
        f"Impact {impact} follows the severity label supplied by the advisory source. "
        "Probability 3 is a documented qualitative baseline for a package version "
        "explicitly marked vulnerable; this check does not measure exploitability, "
        "network reachability or whether vulnerable code paths are used."
    )
    return impact, probability, rationale


def _slug(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", value.upper()).strip("-")[:45] or "UNKNOWN"


def _finding(
    package: InstalledPackage,
    advisory_id: str,
    identifiers: tuple[str, ...],
    severity: str | None,
    summary: str,
    fixed_version: str | None,
    source: str,
    status: FindingStatus,
    *,
    cvss_vector: str | None = None,
    cvss_assessments: tuple[CVEAssessment, ...] | None = None,
    status_detail: str = "",
) -> Finding:
    displayed_id = ", ".join(identifiers) if identifiers else advisory_id
    title = f"{package.name} {package.version} affected by {displayed_id}"
    normalized_severity = severity.upper() if severity else None
    impact, probability, rationale = _risk_profile(
        normalized_severity, cvss_vector, confirmed=status is FindingStatus.FAIL
    )
    evidence = (
        f"Package={package.name}; installed version={package.version}; "
        f"advisory={advisory_id}; identifiers={displayed_id}; "
        f"severity={normalized_severity or 'not provided'}; "
        f"fixed version={fixed_version or 'not provided'}; source={source}"
    )
    if status_detail:
        evidence += f"; source status={status_detail}"

    if fixed_version:
        recommendation = (
            f"Update {package.name} to {fixed_version} or a later security-fixed "
            "version using the distribution's package manager, then rerun the assessment."
        )
    else:
        recommendation = (
            f"Review the advisory and install the latest security-supported version "
            f"of {package.name} when a fix is available; then rerun the assessment."
        )

    if status is FindingStatus.FAIL:
        explanation = (
            f"The selected vulnerability source identifies the installed package version "
            f"as affected. The source and version evidence are listed above. {summary}"
        )
    else:
        explanation = (
            f"The advisory is relevant to the installed package, but the source data or "
            f"version comparison does not support a confirmed vulnerable-state conclusion. "
            f"{summary}"
        )

    if cvss_assessments is None:
        # Keep CVE identifiers visible even when their CVSS vector is absent.
        cvss_assessments = tuple(
            CVEAssessment(cve_id=identifier)
            for identifier in identifiers
            if re.fullmatch(r"CVE-\d{4}-\d+", identifier)
        )

    return Finding(
        rule_id=f"PACKAGE-CVE-{_slug(advisory_id)}-{_slug(package.name)}",
        title=title,
        evidence=evidence,
        explanation=_clean(explanation, 1200),
        recommendation=_clean(recommendation, 600),
        status=status,
        severity=normalized_severity,
        impact=impact,
        probability=probability,
        risk_rationale=rationale,
        cves=cvss_assessments,
    )



def _nvd_cvss_for_cves(
    cve_ids: tuple[str, ...],
    *,
    fetcher=None,
    sleeper=None,
) -> tuple[dict[str, tuple[CVSSScore, ...]], tuple[str, ...]]:
    """Retrieve and cache source-provided NVD CVSS vectors in bounded batches."""
    if fetcher is None:
        fetcher = _http_json
    if sleeper is None:
        sleeper = time.sleep

    identifiers = tuple(sorted({
        value.strip()
        for value in cve_ids
        if isinstance(value, str)
        and re.fullmatch(r"CVE-\d{4}-\d+", value.strip())
    }))

    scores_by_cve: dict[str, tuple[CVSSScore, ...]] = {}
    pending: list[str] = []
    now = time.monotonic()

    for cve_id in identifiers:
        cached = _NVD_CVSS_CACHE.get(cve_id)
        if cached is not None and 0 <= now - cached[0] < NVD_CACHE_TTL_SECONDS:
            scores_by_cve[cve_id] = cached[1]
        else:
            _NVD_CVSS_CACHE.pop(cve_id, None)
            pending.append(cve_id)

    messages: list[str] = []
    metric_types = (
        ("cvssMetricV40", "CVSS_V4"),
        ("cvssMetricV31", "CVSS_V3"),
        ("cvssMetricV30", "CVSS_V3"),
        ("cvssMetricV2", "CVSS_V2"),
    )

    for batch_index, offset in enumerate(range(0, len(pending), NVD_BATCH_SIZE)):
        batch = pending[offset:offset + NVD_BATCH_SIZE]

        # NVD recommends approximately six seconds between public API requests.
        if batch_index:
            sleeper(6.1)

        query = urlencode({
            "cveIds": ",".join(batch),
            "resultsPerPage": str(len(batch)),
        })
        url = f"{NVD_CVES_URL}?{query}"

        try:
            response = fetcher(url)
        except (OSError, TimeoutError, ValueError, subprocess.SubprocessError) as error:
            messages.append(
                f"NVD CVSS batch {batch_index + 1} unavailable: {type(error).__name__}."
            )
            continue

        vulnerabilities = (
            response.get("vulnerabilities")
            if isinstance(response, dict)
            else None
        )
        if not isinstance(vulnerabilities, list):
            continue

        batch_scores: dict[str, list[CVSSScore]] = {
            cve_id: [] for cve_id in batch
        }
        seen: dict[str, dict[tuple[str, str], int]] = {
            cve_id: {} for cve_id in batch
        }
        seen_sources: dict[str, dict[tuple[str, str], set[str]]] = {
            cve_id: {} for cve_id in batch
        }

        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue

            record = item.get("cve")
            if not isinstance(record, dict):
                continue

            cve_id = record.get("id")
            if not isinstance(cve_id, str) or cve_id not in batch_scores:
                continue

            metrics = record.get("metrics")
            if not isinstance(metrics, dict):
                continue

            for metric_name, declared_type in metric_types:
                entries = metrics.get(metric_name, [])
                if not isinstance(entries, list):
                    continue

                for metric in entries:
                    if not isinstance(metric, dict):
                        continue

                    cvss_data = metric.get("cvssData")
                    if not isinstance(cvss_data, dict):
                        continue

                    vector = cvss_data.get("vectorString")
                    if not isinstance(vector, str):
                        continue

                    source_label = (
                        metric.get("source")
                        or record.get("sourceIdentifier")
                        or "NVD"
                    )
                    source_label = _clean(source_label, 100) or "NVD"
                    result = calculate_cvss(
                        vector,
                        declared_type=declared_type,
                        source=f"NVD ({source_label})",
                    )
                    if result is None:
                        continue

                    # Identical version + vector means the same assessment,
                    # even when NVD lists multiple sources for that metric.
                    key = (result.version, result.vector)
                    if key not in seen[cve_id]:
                        seen[cve_id][key] = len(batch_scores[cve_id])
                        seen_sources[cve_id][key] = {source_label}
                        batch_scores[cve_id].append(result)
                    else:
                        seen_sources[cve_id][key].add(source_label)
                        source_names = "; ".join(sorted(seen_sources[cve_id][key]))
                        index = seen[cve_id][key]
                        batch_scores[cve_id][index] = CVSSScore(
                            version=result.version,
                            base_score=result.base_score,
                            severity=result.severity,
                            vector=result.vector,
                            source=f"NVD ({source_names})",
                        )

        cached_at = time.monotonic()
        for cve_id in batch:
            scores = tuple(batch_scores[cve_id])
            scores_by_cve[cve_id] = scores
            _NVD_CVSS_CACHE[cve_id] = (cached_at, scores)

    return scores_by_cve, tuple(messages)


def _arch_tracker_audit(
    inventory: PackageInventory,
    *,
    which=None,
    runner=None,
    fetcher=None,
) -> PackageAudit:
    if fetcher is None:
        fetcher = _http_json

    try:
        records = fetcher(ARCH_TRACKER_URL)
    except (OSError, TimeoutError, ValueError, subprocess.SubprocessError) as error:
        return PackageAudit(
            "Arch Linux Security Tracker", "NOT_ASSESSED", len(inventory.packages),
            messages=(f"Could not retrieve the official Arch security feed: {type(error).__name__}.",),
        )

    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        return PackageAudit(
            "Arch Linux Security Tracker", "ERROR", len(inventory.packages),
            messages=("The Arch security feed did not contain the expected list of advisory records.",),
        )

    installed = {package.name: package for package in inventory.packages}
    findings: list[Finding] = []
    messages: list[str] = []
    unresolved = 0

    # Fetch CVSS only for CVEs belonging to advisories that mention installed
    # packages. The feed's advisory severity is deliberately not copied to CVEs.
    installed_names = set(installed)
    cve_candidates: set[str] = set()

    for candidate in records:
        candidate_state = str(candidate.get("status") or "Unknown").strip().lower()
        if candidate_state not in {"vulnerable", "unknown", "testing"}:
            continue

        raw_candidate_names = candidate.get("packages", [])
        candidate_names = (
            (raw_candidate_names,)
            if isinstance(raw_candidate_names, str)
            else raw_candidate_names
        )
        if not isinstance(candidate_names, (list, tuple)):
            continue
        if not any(
            isinstance(name, str) and name in installed_names
            for name in candidate_names
        ):
            continue

        raw_issues = candidate.get("issues", [])
        if isinstance(raw_issues, list):
            for issue in raw_issues:
                if isinstance(issue, str):
                    cve_id = issue.strip()
                    if re.fullmatch(r"CVE-\d{4}-\d+", cve_id):
                        cve_candidates.add(cve_id)

    cvss_by_cve, cvss_messages = _nvd_cvss_for_cves(
        tuple(sorted(cve_candidates)),
        fetcher=fetcher,
    )
    messages.extend(cvss_messages)

    for record in records:
        advisory_id = str(record.get("name") or "")
        raw_names = record.get("packages", [])
        names = (raw_names,) if isinstance(raw_names, str) else raw_names
        if not advisory_id or not isinstance(names, list):
            continue

        source_state = str(record.get("status") or "Unknown")
        state = source_state.strip().lower()
        if state not in {"vulnerable", "unknown", "testing"}:
            continue

        severity = str(record.get("severity") or "").upper()
        if severity in {"UNKNOWN", "NONE", "N/A"}:
            severity = ""
        fixed_value = record.get("fixed")
        fixed_version = str(fixed_value).strip() if fixed_value else None
        cves_raw = record.get("issues", [])
        cves = tuple(
            sorted({
                str(item).strip()
                for item in cves_raw
                if isinstance(item, str) and re.fullmatch(r"CVE-\d{4}-\d+", item.strip())
            })
        ) if isinstance(cves_raw, list) else ()
        source = f"https://security.archlinux.org/{quote(advisory_id, safe='-')}"

        for package_name in names:
            if not isinstance(package_name, str) or package_name not in installed:
                continue
            package = installed[package_name]

            if fixed_version:
                comparison = _version_compare_arch(
                    package.version, fixed_version, which=which, runner=runner
                )
                if comparison is None:
                    status = FindingStatus.REVIEW
                    status_detail = f"{source_state}; version comparison unavailable"
                elif comparison >= 0:
                    continue
                else:
                    status = (
                        FindingStatus.FAIL if state == "vulnerable"
                        else FindingStatus.REVIEW
                    )
                    status_detail = source_state
            else:
                affected_value = record.get('affected')
                affected_version = (
                    str(affected_value).strip() if affected_value else None
                )
                if not affected_version:
                    status = FindingStatus.REVIEW
                    status_detail = (
                        f"{source_state}; no fixed or affected version provided"
                    )
                else:
                    comparison = _version_compare_arch(
                        package.version,
                        affected_version,
                        which=which,
                        runner=runner,
                    )
                    if comparison is None:
                        status = FindingStatus.REVIEW
                        status_detail = (
                            f"{source_state}; no fixed version; "
                            f"could not compare affected version {affected_version}"
                        )
                    elif comparison > 0:
                        status = FindingStatus.REVIEW
                        status_detail = (
                            f"{source_state}; installed version {package.version} "
                            f"is newer than affected version {affected_version}; "
                            "advisory has no fixed version"
                        )
                    else:
                        status = (
                            FindingStatus.FAIL if state == "vulnerable"
                            else FindingStatus.REVIEW
                        )
                        status_detail = (
                            f"{source_state}; no fixed version; installed version "
                            f"is not newer than affected version {affected_version}"
                        )

            summary = _clean(record.get("type") or "Distribution security advisory.")
            cvss_assessments = tuple(
                CVEAssessment(
                    cve_id=cve_id,
                    cvss=cvss_by_cve.get(cve_id, ()),
                )
                for cve_id in cves
            )
            findings.append(
                _finding(
                    package, advisory_id, cves, severity or None, summary,
                    fixed_version, source, status,
                    cvss_assessments=cvss_assessments,
                    status_detail=status_detail,
                )
            )
            if status is not FindingStatus.FAIL:
                unresolved += 1

    if unresolved:
        messages.append(f"{unresolved} matching Arch advisory record(s) require review.")
    status = "PARTIAL" if unresolved else "OK"
    return PackageAudit(
        "Arch Linux Security Tracker", status, len(inventory.packages),
        tuple(findings), tuple(messages),
    )


def _osv_severity(record: dict[str, Any]) -> tuple[str | None, str | None]:
    database = record.get("database_specific")
    if isinstance(database, dict):
        label = database.get("severity")
        if isinstance(label, str) and label.strip().upper() not in {"UNKNOWN", "N/A", "NONE"}:
            severity = label.strip().upper()
        else:
            severity = None
    else:
        severity = None

    vector = None
    raw_severity = record.get("severity")
    if isinstance(raw_severity, list):
        for entry in raw_severity:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score")
            if isinstance(score, str) and score.startswith(("CVSS:3.0/", "CVSS:3.1/")):
                vector = score
                break
    return severity, vector


def _osv_cvss_assessments(
    record: dict[str, Any],
    cve_ids: tuple[str, ...],
) -> tuple[CVEAssessment, ...]:
    """Calculate CVSS from the source-provided OSV vectors for each CVE alias."""
    raw_severity = record.get("severity")
    if not isinstance(raw_severity, list) or not cve_ids:
        return tuple(CVEAssessment(cve_id=cve_id) for cve_id in cve_ids)

    scores: list = []
    seen: set[tuple[str, str]] = set()

    for entry in raw_severity:
        if not isinstance(entry, dict):
            continue

        vector = entry.get("score")
        declared_type = entry.get("type")
        if not isinstance(vector, str):
            continue
        if declared_type is not None and not isinstance(declared_type, str):
            continue

        result = calculate_cvss(
            vector,
            declared_type=declared_type,
            source="OSV.dev",
        )
        if result is None:
            continue

        key = (result.version, result.vector)
        if key not in seen:
            scores.append(result)
            seen.add(key)

    # An OSV record may have several CVE aliases. Preserve the assessment on
    # each alias rather than collapsing distinct identifiers into one string.
    return tuple(
        CVEAssessment(cve_id=cve_id, cvss=tuple(scores))
        for cve_id in cve_ids
    )


def _osv_fixed_version(record: dict[str, Any], package_name: str) -> str | None:
    affected = record.get("affected")
    if not isinstance(affected, list):
        return None
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package")
        if not isinstance(package, dict) or package.get("name") != package_name:
            continue
        ranges = item.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, dict):
                continue
            events = version_range.get("events", [])
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    return event["fixed"]
    return None


def _osv_query_identity(
    package: InstalledPackage,
    ecosystem: str,
) -> tuple[str, str]:
    """Use Ubuntu source-package metadata when available."""
    if (
        ecosystem.startswith("Ubuntu:")
        and package.source_name
        and package.source_version
    ):
        return package.source_name, package.source_version

    return package.name, package.version


def _osv_audit(inventory: PackageInventory, ecosystem: str, *, fetcher=None) -> PackageAudit:
    if fetcher is None:
        fetcher = _http_json

    packages = list(inventory.packages)
    messages: list[str] = []
    if len(packages) > MAX_OSV_PACKAGES:
        packages = packages[:MAX_OSV_PACKAGES]
        messages.append(
            f"Only the first {MAX_OSV_PACKAGES} packages were checked because of the query budget."
        )

    matched: list[tuple[InstalledPackage, str]] = []
    successful_batches = 0
    failed_batches = 0

    for offset in range(0, len(packages), BATCH_SIZE):
        batch = packages[offset:offset + BATCH_SIZE]
        queries = []
        for package in batch:
            query_name, query_version = _osv_query_identity(package, ecosystem)
            queries.append(
                {
                    "package": {
                        "name": query_name,
                        "ecosystem": ecosystem,
                    },
                    "version": query_version,
                }
            )
        try:
            response = fetcher(OSV_QUERYBATCH_URL, {"queries": queries})
        except (OSError, TimeoutError, ValueError, subprocess.SubprocessError) as error:
            failed_batches += 1
            messages.append(f"OSV batch {offset // BATCH_SIZE + 1} failed: {type(error).__name__}.")
            continue

        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list) or len(results) != len(batch):
            failed_batches += 1
            messages.append(f"OSV batch {offset // BATCH_SIZE + 1} returned an unexpected response.")
            continue

        successful_batches += 1
        for package, result in zip(batch, results):
            if not isinstance(result, dict):
                failed_batches += 1
                continue
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                failed_batches += 1
                continue
            for vuln in vulns:
                if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                    matched.append((package, vuln["id"]))
            if result.get("next_page_token"):
                messages.append(
                    f"OSV returned a pagination token for package {package.name}; "
                    "additional advisory pages were not fetched."
                )

    if failed_batches and not successful_batches:
        return PackageAudit(
            "OSV.dev", "NOT_ASSESSED", len(packages), (),
            tuple(messages or ("No OSV query batch could be completed.",)),
        )

    unique_ids = sorted({advisory_id for _, advisory_id in matched})
    details: dict[str, dict[str, Any]] = {}
    for advisory_id in unique_ids[:MAX_ADVISORY_DETAILS]:
        try:
            response = fetcher(OSV_VULN_URL + quote(advisory_id, safe="-._"), None)
            if isinstance(response, dict):
                details[advisory_id] = response
            else:
                messages.append(f"OSV detail for {advisory_id} had an unexpected format.")
        except (OSError, TimeoutError, ValueError, subprocess.SubprocessError) as error:
            messages.append(f"OSV detail for {advisory_id} was unavailable: {type(error).__name__}.")

    if len(unique_ids) > MAX_ADVISORY_DETAILS:
        messages.append(
            f"Detailed metadata was fetched for at most {MAX_ADVISORY_DETAILS} unique advisory IDs."
        )

    findings: list[Finding] = []
    for package, advisory_id in matched:
        record = details.get(advisory_id, {})
        aliases_raw = record.get("aliases", [])
        aliases = tuple(sorted({
            value for value in aliases_raw
            if isinstance(value, str) and re.fullmatch(r"CVE-\d{4}-\d+", value)
        })) if isinstance(aliases_raw, list) else ()
        cves = aliases
        if not cves and re.fullmatch(r"CVE-\d{4}-\d+", advisory_id):
            cves = (advisory_id,)

        summary = _clean(record.get("summary") or f"OSV reported vulnerability {advisory_id}.", 900)
        severity, vector = _osv_severity(record)
        cvss_assessments = _osv_cvss_assessments(record, cves)
        query_name, _ = _osv_query_identity(package, ecosystem)
        fixed_version = _osv_fixed_version(record, query_name)
        refs = record.get("references", [])
        source = f"https://osv.dev/vulnerability/{quote(advisory_id, safe='-._')}"
        if isinstance(refs, list):
            for reference in refs:
                if isinstance(reference, dict) and isinstance(reference.get("url"), str):
                    source = reference["url"]
                    break

        findings.append(
            _finding(
                package, advisory_id, cves, severity, summary, fixed_version,
                source,
                FindingStatus.FAIL,
                cvss_vector=vector,
                cvss_assessments=cvss_assessments,
                status_detail="OSV query matched the installed package version",
            )
        )

    if failed_batches or messages:
        status = "PARTIAL"
    else:
        status = "OK"

    return PackageAudit(
        "OSV.dev", status, len(packages), tuple(findings), tuple(messages),
    )


def collect_package_audit(inventory: PackageInventory) -> PackageAudit:
    """Query a distribution-appropriate vulnerability source.

    Network access happens only when the caller explicitly invokes package
    vulnerability assessment. The OSV request transmits package names,
    installed versions and the mapped ecosystem; it does not transmit a
    hostname, user accounts, filesystem paths or scan results.
    """
    if inventory.status not in {"OK", "PARTIAL"} or not inventory.packages:
        return PackageAudit(
            "unavailable", "NOT_ASSESSED", 0, (),
            ("Package inventory is incomplete or unavailable; CVE correlation was not run.",),
        )

    if inventory.distribution_id.lower() == "arch":
        return _arch_tracker_audit(inventory)

    ecosystem = _osv_ecosystem(inventory)
    if ecosystem is None:
        return PackageAudit(
            "no validated advisory adapter", "NOT_ASSESSED", len(inventory.packages), (),
            (
                f"No validated CVE ecosystem mapping is configured for "
                f"{inventory.distribution_name} {inventory.release or ''}. "
                "The package inventory is still available, but vulnerability coverage is unassessed.",
            ),
        )

    return _osv_audit(inventory, ecosystem)
