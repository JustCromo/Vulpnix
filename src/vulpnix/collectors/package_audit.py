"""Distribution-aware, read-only package vulnerability lookups."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from vulpnix.findings import Finding, FindingStatus
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
    """Map only distributions with an OSV ecosystem mapping we intend to support."""
    distro = inventory.distribution_id.lower()
    release = inventory.release.strip()

    if distro == "debian" and release:
        major = release.split(".", 1)[0]
        return f"Debian:{major}" if major.isdigit() else None

    if distro == "ubuntu" and re.fullmatch(r"\d{2}\.\d{2}(?:\.\d+)?", release):
        return f"Ubuntu:{release.split('.')[0]}.{release.split('.')[1]}"

    if distro == "alpine" and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", release):
        major, minor = release.split(".")[:2]
        return f"Alpine:v{major}.{minor}"

    if distro == "almalinux" and release:
        major = release.split(".", 1)[0]
        return f"AlmaLinux:{major}" if major.isdigit() else None

    if distro == "rocky" and release:
        major = release.split(".", 1)[0]
        return f"Rocky Linux:{major}" if major.isdigit() else None

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
    )


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
            findings.append(
                _finding(
                    package, advisory_id, cves, severity or None, summary,
                    fixed_version, source, status, status_detail=status_detail,
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
        queries = [
            {"package": {"name": package.name, "ecosystem": ecosystem}, "version": package.version}
            for package in batch
        ]
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
        fixed_version = _osv_fixed_version(record, package.name)
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
                source, FindingStatus.FAIL, cvss_vector=vector,
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
