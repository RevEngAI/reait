#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from subprocess import check_call
from sys import executable
from unittest import main

from utils import BaseTestCase, testlog

import reait.api as api


def run_test_script(fpath: str, *args) -> int:
    cmd = [executable, fpath] + list(args)

    testlog.info("Running '%s'", " ".join(cmd))
    return check_call(cmd, timeout=60)


class TestReait(BaseTestCase):
    def test_1_version(self):
        self.assertEqual(0,
                         run_test_script("src/reait/main.py", "--version"))

    def test_2_upload(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--upload",
                                             "--apikey", api.re_conf['apikey']))
        except Exception:
            self.fail(f"Failed to upload {self._fpath}")

    def test_3_analyse(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--analyse",
                                             "--apikey", api.re_conf['apikey'], "--model", "binnet-0.3-x86-linux"))
        except Exception:
            self.fail(f"Failed to analyse {self._fpath}")
        finally:
            self.test_7_delete()

    def test_4_upload_analyse(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "-A",
                                             "--apikey", api.re_conf['apikey'], "--model", "binnet-0.3-x86-linux"))
        except Exception:
            self.fail(f"Failed to upload and analyse {self._fpath}")

    def test_5_logs(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--logs",
                                             "--apikey", api.re_conf['apikey']))
        except Exception:
            self.fail(f"Failed to get analysis logs {self._fpath}")

    def test_6_status(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--status",
                                             "--apikey", api.re_conf['apikey']))
        except Exception:
            self.fail(f"Failed to get analysis status {self._fpath}")

    def test_7_delete(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--delete",
                                             "--apikey", api.re_conf['apikey']))
        except Exception:
            self.fail(f"Failed to delete {self._fpath}")


if __name__ == "__main__":
    main()
