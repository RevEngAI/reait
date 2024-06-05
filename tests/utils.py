# -*- coding: utf-8 -*-
import abc
import logging

from os import listdir

from os.path import join
from pathlib import Path
from random import choice
from sys import path, stdout

from unittest import TestCase

from requests import get, HTTPError

CWD = Path(__file__).parent

# Make it possible to run this file from the root dir of reait without installing reait
path.insert(0, (CWD / ".." / "src").as_posix())

import reait.api as api


# Create a global logger object
testlog = logging.getLogger("run_tests")
testlog.setLevel(logging.DEBUG)
testlog.addHandler(logging.StreamHandler(stdout))


class BaseTestCase(TestCase):
    __metaclass__ = abc.ABCMeta

    _cwd: str = None
    _fpath: str = None
    _platform: str = None

    @classmethod
    def setUpClass(cls):
        cls._cwd = join(CWD, "binaries")

        cls._platform = choice(listdir(cls._cwd))

        # Randomly selects a binary from the binaries folder
        cls._fpath = join(cls._cwd, cls._platform, choice(listdir(join(cls._cwd, cls._platform))))

        api.re_conf["model"] += "-" + cls._platform

        # Deletes all previous analyses from the RevEng.AI platform
        cls._cleanup_binaries(cls._fpath)

    @staticmethod
    def _cleanup_binaries(fpath: str) -> None:
        try:
            bin_id = api.re_binary_id(fpath)

            testlog.info("Getting all previous analyses for %s", bin_id)

            binaries = api.reveng_req(get, "v1/search",
                                      json_data={"sha_256_hash": bin_id}).json()["query_results"]

            for binary in binaries:
                testlog.info("Deleting analysis with binary ID: %d", binary["binary_id"])

                api.RE_delete(fpath, binary["binary_id"])
        except HTTPError as e:
            testlog.error("Something weird happened while deleting all previous analyses. %s", e)
