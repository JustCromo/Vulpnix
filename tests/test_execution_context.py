from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulpnix.context import Environment, current_execution_context, detect_environment


class EnvironmentDetectionTests(unittest.TestCase):
    def _root(self, osrelease: str | None, markers: tuple[str, ...] = ()) -> Path:
        root = Path(self._tmp.name)
        if osrelease is not None:
            path = root / "proc/sys/kernel/osrelease"
            path.parent.mkdir(parents=True)
            path.write_text(osrelease, encoding="utf-8")
        for marker in markers:
            (root / marker).touch()
        return root

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_wsl_kernel_release_is_detected(self):
        root = self._root("6.18.33.2-microsoft-standard-WSL2\n")
        self.assertIs(detect_environment(root=root, environ={}), Environment.WSL)

    def test_wsl_environment_variable_is_detected(self):
        root = self._root("6.12.0-arch1-1\n")
        environ = {"WSL_DISTRO_NAME": "Ubuntu"}
        self.assertIs(detect_environment(root=root, environ=environ), Environment.WSL)

    def test_container_markers_are_detected(self):
        for marker in (".dockerenv",):
            with self.subTest(marker=marker):
                root = self._root("6.12.0-arch1-1\n", (marker,))
                self.assertIs(detect_environment(root=root, environ={}), Environment.CONTAINER)

    def test_container_environment_variable_is_detected(self):
        root = self._root("6.12.0\n")
        environ = {"container": "podman"}
        self.assertIs(detect_environment(root=root, environ=environ), Environment.CONTAINER)

    def test_plain_linux_is_native(self):
        root = self._root("6.12.0-arch1-1\n")
        self.assertIs(detect_environment(root=root, environ={}), Environment.NATIVE)

    def test_missing_evidence_is_unknown_not_guessed(self):
        root = self._root(None)
        self.assertIs(detect_environment(root=root, environ={}), Environment.UNKNOWN)

    def test_context_inherits_process_privilege(self):
        with patch("vulpnix.scan.privilege.os.geteuid", return_value=1000):
            ctx = current_execution_context()
        self.assertFalse(ctx.privileged)
        self.assertEqual(ctx.privilege.mode, "ROOTLESS")


if __name__ == "__main__":
    unittest.main()
