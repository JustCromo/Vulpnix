"""Failures caused by the observed system, as opposed to bugs in Vulpnix."""

import subprocess

# Missing files, unreadable output, failing or slow commands. Anything else
# (KeyError, TypeError, ...) is a Vulpnix bug and must surface, never be
# reported as a property of the host.
EXPECTED_FAILURES = (OSError, subprocess.SubprocessError, UnicodeError, ValueError)
