#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from os.path import isdir, dirname

from unittest import TestLoader, TextTestRunner

from utils import testlog


def main() -> int:
    if not isdir("tests"):
        testlog.error("!! Please execute from the root directory of reait")
        return 1
    else:
        tests = TestLoader().discover(dirname(__file__))
        result = TextTestRunner(verbosity=2).run(tests)

        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    exit(main())
