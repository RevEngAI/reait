#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from unittest import main

from .utils import BaseTestCase

import reait.api as api


class TestAPIs(BaseTestCase):
    def test_0_conf(self):
        self.assertGreaterEqual(len(api.re_conf), 3)
        self.assertTrue(all(api.re_conf[key] for key in ("apikey", "host", "model",)))
        self.assertNotEqual(api.re_conf["apikey"], "l1br3")

    def test_1_upload(self):
        try:
            response = api.RE_upload(self._fpath).json()

            self.assertTrue(response["success"], "Upload file has failed")
            self.assertEqual(response["sha_256_hash"], api.re_binary_id(self._fpath), "SHA-256 mismatch")
        except Exception:
            self.fail(f"Failed to upload {self._fpath}")

    def test_2_analysis(self):
        try:
            response = api.RE_analyse(self._fpath, model_name="binnet-0.3-x86-linux").json()

            self.assertTrue(response["success"], "Analysis file has failed")
            self.assertIsInstance(response["binary_id"], int)
        except Exception:
            self.fail(f"Failed to analyse {self._fpath}")

    def test_3_analysis_failure(self):
        try:
            # Should raise a ReaitError because of duplicate analysis
            api.RE_analyse(self._fpath, model_name="binnet-0.3-x86-linux")

            self.fail(f"Duplicate analysis for {self._fpath}")
        except Exception as e:
            self.assertIsInstance(e, api.ReaitError)
            self.assertIsNotNone(e.response)
            self.assertEqual(e.response.status_code, 404)
            self.assertFalse(e.response.json()["success"])

    def test_4_logs(self):
        try:
            response = api.RE_logs(self._fpath).json()

            self.assertTrue(response["success"], "Analysis file has failed")
            self.assertIsNotNone(response["logs"], "Empty logs analysis")
        except Exception:
            self.fail("Failed to retrieve logs")

    def test_5_delete(self):
        try:
            response = api.RE_delete(self._fpath).json()

            self.assertTrue(response["success"], "Delete file has failed")
        except Exception:
            self.fail(f"Failed to delete {self._fpath}")


if __name__ == "__main__":
    main()