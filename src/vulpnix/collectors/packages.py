"""Read-only installed-package inventory with distribution capability detection."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from vulpnix.models.packages import InstalledPackage, PackageInventory


MANAGER_BY_ID = {
    "debian": "dpkg-query",
    "ubuntu": "dpkg-query",
    "linuxmint": "dpkg-query",
    "pop": "dpkg-query",
    "raspbian": "dpkg-query",
    "fedora": "rpm",
    "rhel": "rpm",
    "centos": "rpm",
    "rocky": "rpm",
    "almalinux": "rpm",
    "ol": "rpm",
    "amzn": "rpm",
    "opensuse": "rpm",
    "opensuse-leap": "rpm",
    "opensuse-tumbleweed": "rpm",
    "sles": "rpm",
    "suse": "rpm",
    "alpine": "apk",
    "arch": "pacman",
    "manjaro": "pacman",
    "endeavouros": "pacman",
    "artix": "pacman",
    "void": "xbps-query",
}

MANAGER_COMMANDS = {
    "pacman": ("pacman", "-Q"),
    "dpkg-query": (
        "dpkg-query",
        "-W",
        r"-f=${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n",
    ),
    "rpm": (
        "rpm",
        "-qa",
        "--qf",
        r"%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n",
    ),
    "apk": ("apk", "info", "-v"),
    "xbps-query": ("xbps-query", "-l"),
}


def read_os_release(path: str | Path = "/etc/os-release") -> dict[str, str]:
    """Parse os-release as data; never execute or source the file."""
    result: dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return result

    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw_value = line.partition("=")
        key = key.strip()
        if not key or not re.fullmatch(r"[A-Z0-9_]+", key):
            continue
        try:
            values = shlex.split(raw_value, comments=False, posix=True)
            value = values[0] if values else ""
        except ValueError:
            continue
        result[key] = value
    return result


def _manager_for(
    distro_id: str,
    id_like: str,
    available: dict[str, str],
) -> str | None:
    """Choose an adapter using the detected distro before any fallback."""
    for candidate in (distro_id, *id_like.split()):
        manager = MANAGER_BY_ID.get(candidate.lower())
        if manager:
            # Preserve the distribution's expected manager even when missing.
            # The caller will report NOT_ASSESSED if the executable is absent.
            return manager

    # An unidentified distribution is safe to probe only when one supported
    # package manager is available; don't guess between multiple databases.
    if len(available) == 1:
        return next(iter(available))
    return None


def _parse_package_lines(
    manager: str,
    output: str,
) -> tuple[tuple[InstalledPackage, ...], int]:
    packages: list[InstalledPackage] = []
    malformed = 0

    for line in output.splitlines():
        if not line.strip():
            continue

        source_name: str | None = None
        source_version: str | None = None

        if manager == "pacman":
            parts = line.split(None, 1)
            if len(parts) != 2:
                malformed += 1
                continue
            name, version = parts
            architecture = None

        elif manager in {"dpkg-query", "rpm"}:
            parts = line.split("\t")
            if len(parts) < 2 or not parts[0].strip() or not parts[1].strip():
                malformed += 1
                continue
            name, version = parts[0].strip(), parts[1].strip()
            architecture = parts[2].strip() if len(parts) > 2 else None
            if architecture in ("", "(none)", "unknown"):
                architecture = None

            if manager == "dpkg-query":
                source_name = parts[3].strip() if len(parts) > 3 else None
                source_version = parts[4].strip() if len(parts) > 4 else None

                if source_name in ("", "(none)", "unknown"):
                    source_name = None
                if source_version in ("", "(none)", "unknown"):
                    source_version = None

        elif manager == "apk":
            # Alpine package names may contain hyphens. The version starts
            # with a digit, so split at the first hyphen before that digit.
            match = re.match(r"^(.+?)-([0-9][A-Za-z0-9._+~:\-]*)$", line.strip())
            if not match:
                malformed += 1
                continue
            name, version = match.groups()
            architecture = None

        elif manager == "xbps-query":
            # xbps-query -l reports a state followed by pkgver and a description.
            # Only fully installed packages are included in the inventory.
            parts = line.split(None, 2)
            if len(parts) < 2:
                malformed += 1
                continue

            state, package_version = parts[0], parts[1]
            if state in {"uu", "hr", "??"}:
                continue
            if state not in {"ii", "[*]"}:
                malformed += 1
                continue

            match = re.fullmatch(
                r"(.+)-([0-9][A-Za-z0-9._+~:]*)",
                package_version,
            )
            if not match:
                malformed += 1
                continue

            name, version = match.groups()
            architecture = None

        else:
            malformed += 1
            continue

        packages.append(InstalledPackage(name, version, architecture, source_name, source_version))

    # Stable ordering makes reports and tests deterministic.
    packages.sort(key=lambda item: (item.name, item.version, item.architecture or ""))
    return tuple(packages), malformed


def collect_package_inventory(
    *,
    os_release_path: str | Path = "/etc/os-release",
    which=None,
    runner=None,
) -> PackageInventory:
    """Collect installed packages using one detected local package database.

    The collector does not install, remove or update packages. Missing tools,
    unsupported distributions, command failures and malformed output remain
    explicit instead of being treated as evidence that software is safe.
    """
    if which is None:
        which = shutil.which
    if runner is None:
        runner = subprocess.run

    release = read_os_release(os_release_path)
    distro_id = release.get("ID", "").lower()
    distro_name = release.get("PRETTY_NAME") or release.get("NAME") or distro_id or "Unknown Linux"
    version_id = release.get("VERSION_ID", "")
    id_like = release.get("ID_LIKE", "")

    # Probe each executable once. Availability is a capability observation,
    # not proof that a particular distribution uses that package database.
    available: dict[str, str] = {}
    for candidate_manager in MANAGER_COMMANDS:
        executable_path = which(candidate_manager)
        if executable_path:
            available[candidate_manager] = executable_path
    manager = _manager_for(distro_id, id_like, available)

    if manager is None:
        message = (
            "No supported package-manager adapter could be selected reliably. "
            "The distribution may be unsupported or multiple package managers "
            "may be present."
        )
        return PackageInventory(
            distro_id, distro_name, version_id, "unavailable", (),
            "NOT_ASSESSED", (message,),
        )

    executable = available.get(manager) or which(manager)
    if not executable:
        return PackageInventory(
            distro_id, distro_name, version_id, manager, (),
            "NOT_ASSESSED",
            (f"The detected package manager {manager} is not available.",),
        )

    command = [executable, *MANAGER_COMMANDS[manager][1:]]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
    }

    try:
        result = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            shell=False,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return PackageInventory(
            distro_id, distro_name, version_id, manager, (),
            "ERROR",
            (f"Package inventory command failed: {type(error).__name__}.",),
        )

    if result.returncode != 0:
        return PackageInventory(
            distro_id, distro_name, version_id, manager, (),
            "ERROR",
            (f"{manager} exited with status {result.returncode}.",),
        )

    packages, malformed = _parse_package_lines(manager, result.stdout or "")
    if not packages:
        return PackageInventory(
            distro_id, distro_name, version_id, manager, (),
            "ERROR",
            ("The package manager returned no usable package records.",),
        )

    messages = ()
    status = "OK"
    if malformed:
        status = "PARTIAL"
        messages = (
            f"{malformed} package record(s) were malformed and skipped.",
        )

    return PackageInventory(
        distro_id, distro_name, version_id, manager, packages,
        status, messages,
    )
