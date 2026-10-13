"""Metadata-only inspection of OpenSSH host private-key files."""

import os
from pathlib import Path
import stat

from vulpnix.models import SSHHostKeyObservation


def collect_ssh_host_key_metadata(root: str | Path = "/etc/ssh") -> tuple[SSHHostKeyObservation, ...]:
    """Inspect names, ownership, type, and mode; never open or read key contents."""
    directory = Path(root)
    observations: list[SSHHostKeyObservation] = []
    try:
        with os.scandir(directory) as entries:
            candidates = sorted(
                (entry for entry in entries if entry.name.startswith("ssh_host_") and entry.name.endswith("_key")),
                key=lambda entry: entry.name,
            )
            for entry in candidates:
                path = str(directory / entry.name)
                try:
                    metadata = entry.stat(follow_symlinks=False)
                    mode = stat.S_IMODE(metadata.st_mode)
                    observations.append(SSHHostKeyObservation(
                        path=path,
                        owner_uid=metadata.st_uid,
                        mode=mode,
                        is_regular=stat.S_ISREG(metadata.st_mode),
                        is_symlink=stat.S_ISLNK(metadata.st_mode),
                    ))
                except PermissionError:
                    observations.append(SSHHostKeyObservation(path, None, None, None, False, "permission denied"))
                except OSError as error:
                    observations.append(SSHHostKeyObservation(path, None, None, None, False, f"metadata unavailable ({type(error).__name__})"))
    except FileNotFoundError:
        return (SSHHostKeyObservation(str(directory), None, None, None, False, "SSH configuration directory is not present"),)
    except PermissionError:
        return (SSHHostKeyObservation(str(directory), None, None, None, False, "permission denied reading SSH configuration directory"),)
    except OSError as error:
        return (SSHHostKeyObservation(str(directory), None, None, None, False, f"SSH configuration directory unavailable ({type(error).__name__})"),)

    if not observations:
        observations.append(SSHHostKeyObservation(str(directory), None, None, None, False, "no host private-key files found"))
    return tuple(observations)
