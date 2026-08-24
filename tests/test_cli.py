# Copyright (c) 2025, Oracle and/or its affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later


import os
import sys
import tempfile
import traceback
import types
from unittest import mock

import drgn
import drgn.cli
from tests import TestCase


class TestCli(TestCase):
    @staticmethod
    def _debug_info_args(**kwargs):
        args = {
            "debug_directories": None,
            "debug_link_directories": None,
            "kernel_directories": None,
            "no_default_debug_directories": False,
            "no_default_debug_link_directories": False,
            "no_default_kernel_directories": False,
            "default_symbols": None,
            "symbols": None,
            "extra_symbols": None,
            "btf": False,
            "btf_file": None,
        }
        args.update(kwargs)
        return types.SimpleNamespace(**args)

    @staticmethod
    def _debug_info_prog(*, missing=False):
        prog = mock.Mock()
        prog.debug_info_options = types.SimpleNamespace(
            directories=(), debug_link_directories=(), kernel_directories=()
        )
        if missing:
            prog.load_debug_info.side_effect = drgn.MissingDebugInfoError(
                "missing main debugging information"
            )
            module = prog.main_module.return_value
            module.wants_debug_file.return_value = True
        return prog

    def test_btf_fallback(self):
        prog = self._debug_info_prog(missing=True)
        args = self._debug_info_args(btf=True)
        with mock.patch(
            "drgn.helpers.linux.btf.load_builtin_btf"
        ) as load_builtin_btf, self.assertLogs("drgn", level="WARNING") as logs:
            drgn.cli._load_debugging_symbols(prog, args)
        load_builtin_btf.assert_called_once_with(prog, path=None)
        self.assertIn("missing main debugging information", "\n".join(logs.output))

    def test_btf_is_only_a_fallback(self):
        prog = self._debug_info_prog()
        args = self._debug_info_args(btf=True)
        with mock.patch("drgn.helpers.linux.btf.load_builtin_btf") as load_builtin_btf:
            drgn.cli._load_debugging_symbols(prog, args)
        load_builtin_btf.assert_not_called()

    def test_btf_file_forces_loading(self):
        prog = self._debug_info_prog()
        args = self._debug_info_args(btf_file="vmlinux")
        with mock.patch("drgn.helpers.linux.btf.load_builtin_btf") as load_builtin_btf:
            drgn.cli._load_debugging_symbols(prog, args)
        load_builtin_btf.assert_called_once_with(prog, path="vmlinux")

    def test_no_default_symbols_btf_only(self):
        prog = self._debug_info_prog()
        args = self._debug_info_args(default_symbols={}, btf=True)
        with mock.patch("drgn.helpers.linux.btf.load_builtin_btf") as load_builtin_btf:
            drgn.cli._load_debugging_symbols(prog, args)
        load_builtin_btf.assert_called_once_with(prog, path=None)

    def test_btf_error_diagnostic(self):
        prog = self._debug_info_prog(missing=True)
        args = self._debug_info_args(btf=True)
        with mock.patch(
            "drgn.helpers.linux.btf.load_builtin_btf",
            side_effect=NotImplementedError("drgn was not built with libbpf support"),
        ), self.assertLogs("drgn", level="CRITICAL") as logs:
            drgn.cli._load_debugging_symbols(prog, args)
        self.assertIn("drgn was not built with libbpf support", "\n".join(logs.output))

    def run_cli(self, args, *, input=None):
        stdout_r, stdout_w = os.pipe()
        stderr_r, stderr_w = os.pipe()
        if input is not None:
            stdin_r, stdin_w = os.pipe()

        pid = os.fork()
        if pid == 0:
            try:
                os.close(stdout_r)
                sys.stdout = open(stdout_w, "w")
                os.close(stderr_r)
                sys.stderr = open(stderr_w, "w")

                if input is not None:
                    os.close(stdin_w)
                    sys.stdin = open(stdin_r, "r")

                sys.argv = ["drgn"] + args

                drgn.cli._main()
            finally:
                exception = sys.exc_info()[1] is not None
                if exception:
                    traceback.print_exc()
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(1 if exception else 0)

        os.close(stdout_w)
        os.close(stderr_w)

        if input is not None:
            os.close(stdin_r)
            with open(stdin_w, "w") as f:
                f.write(input)

        with open(stdout_r, "r") as f:
            stdout = f.read()
        with open(stderr_r, "r") as f:
            stderr = f.read()

        _, wstatus = os.waitpid(pid, 0)
        if not os.WIFEXITED(wstatus) or os.WEXITSTATUS(wstatus) != 0:
            if os.WIFEXITED(wstatus):
                msg = f"Exited with status {os.WEXITSTATUS(wstatus)}"
            elif os.WIFSIGNALED(wstatus):
                msg = f"Terminated by signal {os.WTERMSIG(wstatus)}"
            else:
                msg = "Exited abnormally"
            self.fail(
                f"""\
{msg}
STDOUT:
{stdout}
STDERR:
{stderr}
"""
            )

        return types.SimpleNamespace(stdout=stdout, stderr=stderr)

    def test_e(self):
        script = r"""
import sys

assert drgn.get_default_prog() is prog
assert __name__ == "__main__"
assert "__file__" not in globals()
assert sys.path[0] == ""
print(sys.argv)
"""
        proc = self.run_cli(
            ["--quiet", "--pid", "0", "--no-default-symbols", "-e", script, "pass"]
        )
        self.assertEqual(proc.stdout, "['-e', 'pass']\n")

    def test_e_empty(self):
        self.run_cli(
            ["--quiet", "--pid", "0", "--no-default-symbols", "-e", ""],
            # This shouldn't be executed.
            input="raise Exception('-e was ignored')",
        )

    def test_script(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(
                rb"""
assert "drgn" not in globals()

import drgn
import os.path
import sys

assert drgn.get_default_prog() is prog
assert __name__ == "__main__"
assert __file__ == sys.argv[0]
assert sys.path[0] == os.path.dirname(__file__)
print(sys.argv)
"""
            )
            f.flush()
            proc = self.run_cli(
                ["--quiet", "--pid", "0", "--no-default-symbols", f.name, "pass"]
            )
            self.assertEqual(proc.stdout, f"[{f.name!r}, 'pass']\n")

    def test_pipe(self):
        script = r"""
import sys

assert drgn.get_default_prog() is prog
assert __name__ == "__main__"
assert __file__ == "<stdin>"
assert sys.path[0] == ""
# Dummy if statement to test handling of multi-line blocks.
if True:
    print(sys.argv)
"""
        proc = self.run_cli(
            ["--quiet", "--pid", "0", "--no-default-symbols"], input=script
        )
        self.assertEqual(proc.stdout, "['']\n")
