"""Version-independent CVSS vector parsing and base score calculation."""

from cvss import CVSS2, CVSS3, CVSS4

from vulpnix.findings import CVSSScore


def calculate_cvss(
    vector: object,
    *,
    declared_type: str | None = None,
    source: str | None = None,
) -> CVSSScore | None:
    """Calculate CVSS metadata from a validated source-provided vector.

    Return None for missing, unsupported, mismatched or malformed vectors.
    The source severity label is never converted into a synthetic CVSS score.
    """
    if not isinstance(vector, str):
        return None

    raw_vector = vector.strip()
    if not raw_vector:
        return None

    kind = declared_type.strip().upper() if isinstance(declared_type, str) else None

    if raw_vector.startswith("CVSS:4.0/"):
        if kind not in {None, "CVSS_V4"}:
            return None
        calculator = CVSS4
        version = "4.0"
        expected_kind = "CVSS_V4"
    elif raw_vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        if kind not in {None, "CVSS_V3"}:
            return None
        calculator = CVSS3
        version = raw_vector.split("/", 1)[0].removeprefix("CVSS:")
        expected_kind = "CVSS_V3"
    elif kind == "CVSS_V2" or (
        kind is None and raw_vector.startswith("AV:")
    ):
        # CVSS v2 vectors use the unprefixed AV/AC/Au/C/I/A syntax.
        if raw_vector.startswith("CVSS:"):
            return None
        calculator = CVSS2
        version = "2.0"
        expected_kind = "CVSS_V2"
    else:
        return None

    if kind is not None and kind != expected_kind:
        return None

    try:
        result = calculator(raw_vector)
        scores = result.scores()
        severities = result.severities()
        if not scores or not severities:
            return None

        score = float(scores[0])
        severity = str(severities[0] or "None").upper()
        canonical_vector = result.clean_vector()
        if not canonical_vector:
            return None

        return CVSSScore(
            version=version,
            base_score=score,
            severity=severity,
            vector=canonical_vector,
            source=source.strip() if isinstance(source, str) and source.strip() else None,
        )
    except Exception:
        # Advisory data is external input: a bad vector must not abort a scan.
        return None
