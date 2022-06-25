import os
import pathlib
import sw_luadocs.which
import tempfile
import unittest


class TestEnvPath(unittest.TestCase):
    def test_nonexistent(self):
        env_key = "TEST"
        env_bak = os.environ.pop(env_key, None)
        try:
            exe = sw_luadocs.which.envpath(env_key, "a", "b", "c")
            self.assertIsNone(exe)
        finally:
            if env_bak is not None:
                os.environ[env_key] = env_bak

    def test_exist(self):
        env_key = "TEST"
        env_bak = os.environ.get(env_key)
        try:
            os.environ[env_key] = "TEST"
            exe = sw_luadocs.which.envpath(env_key, "a", "b", "c")
            self.assertEqual(exe, pathlib.Path("TEST", "a", "b", "c"))
        finally:
            if env_bak is not None:
                os.environ[env_key] = env_bak
            else:
                os.environ.pop(env_key, None)


class TestWhich(unittest.TestCase):
    def test_empty(self):
        exe = sw_luadocs.which.which([])
        self.assertIsNone(exe)

    def test_mode(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            f = pathlib.Path(tmpdirname, "a")
            f.touch()
            f.chmod(0o444)

            exe = sw_luadocs.which.which([f], mode=os.F_OK | os.W_OK)
            self.assertIsNone(exe)

    def test_main(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            pathlib.Path(tmpdirname, "3").touch()

            for input_exe_list, expected_exe in [
                (
                    [
                        pathlib.Path(tmpdirname, "1"),
                        pathlib.Path(tmpdirname, "2"),
                        pathlib.Path(tmpdirname, "3"),
                    ],
                    pathlib.Path(tmpdirname, "3"),
                ),
                (
                    [
                        str(pathlib.Path(tmpdirname, "1")),
                        str(pathlib.Path(tmpdirname, "2")),
                        str(pathlib.Path(tmpdirname, "3")),
                    ],
                    pathlib.Path(tmpdirname, "3"),
                ),
            ]:
                with self.subTest(exe_list=input_exe_list):
                    actual_exe = sw_luadocs.which.which(input_exe_list)
                    self.assertEqual(actual_exe, expected_exe)
