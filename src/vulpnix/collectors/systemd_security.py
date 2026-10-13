"""Metadata-only checks for systemd service unit fragments and drop-ins."""

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

from vulpnix.models import Service, UnitFileObservation

_SYSTEMD_PATHS = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
)
_SYSTEMD_PATHS_NORMALIZED = tuple(os.path.normpath(item) for item in _SYSTEMD_PATHS)
_VALID_UNIT_NAME = re.compile(r"^[A-Za-z0-9_.@:+\\-]+\.service$")


def _parse_show_output(
    output: str,
) -> tuple[
    tuple[str, str, tuple[str, ...], str | None, tuple[str, ...], str | None],
    ...,
]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}

    def flush() -> None:
        nonlocal current
        if current:
            records.append(current)
            current = {}

    for line in output.splitlines():
        if not line.strip():
            flush()
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "Id" and key in current:
            flush()
        current[key] = value
    flush()

    parsed = []
    for record in records:
        unit = record.get("Id", "")
        if not _VALID_UNIT_NAME.fullmatch(unit):
            continue

        names = tuple(dict.fromkeys(
            name
            for name in (unit, *record.get("Names", "").split())
            if _VALID_UNIT_NAME.fullmatch(name)
        ))
        fragment = record.get("FragmentPath", "")
        dropins = tuple(
            item for item in record.get("DropInPaths", "").split() if item
        )
        unit_file_state = record.get("UnitFileState") or None
        load_state = record.get("LoadState") or None

        parsed.append(
            (unit, fragment, dropins, unit_file_state, names, load_state)
        )

    return tuple(parsed)


def _allowed_unit_path(raw_path: str) -> bool:
    if not raw_path or not os.path.isabs(raw_path):
        return False
    if ".." in Path(raw_path).parts:
        return False
    normalized = os.path.normpath(raw_path)
    return any(
        normalized == base or normalized.startswith(base + os.sep)
        for base in _SYSTEMD_PATHS_NORMALIZED
    )


def _inspect_path(unit: str, path: str) -> UnitFileObservation:
    if not _allowed_unit_path(path):
        return UnitFileObservation(unit, path, None, None, None, False, "path was outside approved systemd unit directories")
    try:
        info = os.lstat(path)
    except PermissionError:
        return UnitFileObservation(unit, path, None, None, None, False, "permission denied")
    except FileNotFoundError:
        return UnitFileObservation(unit, path, None, None, None, False, "file does not exist")
    except OSError as error:
        return UnitFileObservation(unit, path, None, None, None, False, f"metadata unavailable ({type(error).__name__})")

    return UnitFileObservation(
        unit=unit,
        path=path,
        owner_uid=info.st_uid,
        mode=stat.S_IMODE(info.st_mode),
        is_regular=stat.S_ISREG(info.st_mode),
        is_symlink=stat.S_ISLNK(info.st_mode),
    )


def collect_service_unit_file_metadata(
    services: tuple[Service, ...],
    *,
    max_units: int = 120,
) -> tuple[tuple[UnitFileObservation, ...], tuple[str, ...]]:
    """Query fragment/drop-in paths in one bounded systemctl call, then inspect metadata only."""
    candidate_services = tuple(
        service.name for service in services
        if _VALID_UNIT_NAME.fullmatch(service.name) and not service.name.startswith("-")
    )
    review: list[str] = []
    if len(candidate_services) > max_units:
        review.append(
            f"Only the first {max_units} unit(s) were considered due to the unit budget"
        )
        candidate_services = candidate_services[:max_units]

    template_services = tuple(
        name for name in candidate_services if name.endswith("@.service")
    )
    valid_services = tuple(
        name for name in candidate_services if not name.endswith("@.service")
    )
    review.extend(
        f"Template unit {name} was not queried because it has no instance; "
        "its file metadata remains unassessed"
        for name in template_services
    )
    if not valid_services:
        return (), tuple((*review, "No service units were available for unit-file metadata assessment"))

    systemctl = shutil.which("systemctl", path="/usr/bin:/bin:/usr/sbin:/sbin")
    if systemctl is None:
        raise FileNotFoundError("systemctl is not installed")
    result = subprocess.run(
        [systemctl, "--system", "show", "--no-pager", "--property=Id,Names,LoadState,FragmentPath,DropInPaths,UnitFileState", *valid_services],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=12,
        shell=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": ""},
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, result.args, output=result.stdout, stderr=result.stderr)

    records = _parse_show_output(result.stdout)
    if not records:
        return (), tuple((*review, "systemctl did not return recognizable unit file metadata"))

    observations: list[UnitFileObservation] = []
    seen_paths: set[tuple[str, str]] = set()
    returned_names: set[str] = set()

    for unit, fragment, dropins, unit_file_state, names, load_state in records:
        returned_names.update(names)

        if load_state == "not-found":
            review.append(
                f"{unit} was not found by systemd; "
                "its unit-file metadata remains unassessed"
            )
            continue

        if unit_file_state in {"masked", "masked-runtime"}:
            review.append(
                f"{unit} is {unit_file_state}; its fragment metadata was not assessed "
                "because the unit is masked"
            )
            continue

        if not fragment:
            review.append(
                f"{unit} has no FragmentPath; its fragment metadata remains unassessed"
            )

        paths = (() if not fragment or fragment == "/dev/null" else (fragment,)) + dropins
        for file_path in paths:
            key = (unit, file_path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            observations.append(_inspect_path(unit, file_path))

    missing_names = set(valid_services) - returned_names
    if missing_names:
        names_text = ", ".join(sorted(missing_names))
        review.append(
            f"systemctl returned no unit record for {len(missing_names)} "
            f"requested unit(s): {names_text}"
        )

    return tuple(observations), tuple(review)
