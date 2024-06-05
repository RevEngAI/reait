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
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py", "--version"))
        except Exception as e:
            testlog.error("Something went wrong when displaying version. %s", e)

    def test_2_upload(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--upload",
                                             "--apikey", api.re_conf["apikey"]))
        except Exception as e:
            testlog.error("Something went wrong when upload binary for analysis. %s", e)

    def test_3_analyse(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--analyse", "--duplicate",
                                             "--apikey", api.re_conf["apikey"],
                                             "--model", api.re_conf["model"]))
        except Exception as e:
            testlog.error("Something went wrong when start analysis. %s", e)
        finally:
            self._cleanup_binaries(self._fpath)

    def test_4_upload_analyse(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "-A", "--duplicate",
                                             "--apikey", api.re_conf["apikey"],
                                             "--model", api.re_conf["model"]))
        except Exception as e:
            testlog.error("Something went wrong when upload + start analysis. %s", e)

    def test_5_logs(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--logs",
                                             "--apikey", api.re_conf["apikey"]))
        except Exception as e:
            testlog.error("Something went wrong when getting logs analysis. %s", e)

    def test_6_status(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--status",
                                             "--apikey", api.re_conf["apikey"]))
        except Exception as e:
            testlog.error("Something went wrong when getting status. %s", e)

    def test_7_delete(self):
        try:
            self.assertEqual(0,
                             run_test_script("src/reait/main.py",
                                             "--binary", self._fpath, "--delete",
                                             "--apikey", api.re_conf["apikey"]))
        except Exception as e:
            testlog.error("Something went wrong when deleting analysis. %s", e)


if __name__ == "__main__":
    main()
