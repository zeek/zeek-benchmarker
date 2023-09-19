import datetime
import hmac
import time
import unittest
from unittest import mock

from zeek_benchmarker.app import create_app, is_valid_branch_name


@mock.patch("zeek_benchmarker.app.enqueue_job")
class TestApi(unittest.TestCase):
    def setUp(self):
        self._test_hmac_key = b"test-key"

        self.app = create_app(
            config={
                "TESTING": True,
                "TEST": True,
                "ALLOWED_BUILD_URLS": ["http://localhost:8080/"],
                "HMAC_KEY": "test-key",
            }
        )
        self._test_client = self.app.test_client()

        # Hmac test data for re-use in tests
        self._test_ts = int(time.time())
        self._test_build_hash = (
            "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
        )
        self._test_zeek_digest = self.hmac_digest(
            "/zeek", self._test_ts, self._test_build_hash
        )

        self.enqueue_job_result_mock = mock.MagicMock()
        self.enqueue_job_result_mock.id = "test-job-id"
        self.enqueue_job_result_mock.enqueued_at = datetime.datetime.fromtimestamp(
            1694690494
        )

    def tearDown(self):
        pass

    def hmac_digest(self, path, timestamp, build_hash):
        hmac_msg = f"{path:s}-{timestamp:d}-{build_hash:s}\n".encode()
        return hmac.new(self._test_hmac_key, hmac_msg, "sha256").hexdigest()

    def test_zeek_good(self, enqueue_job_mock):
        enqueue_job_mock.return_value = self.enqueue_job_result_mock

        r = self._test_client.post(
            "/zeek",
            query_string={
                "branch": "test-branch",
                "build": "http://localhost:8080/build.tgz",
                "build_hash": self._test_build_hash,
            },
            headers={
                "Zeek-HMAC": self._test_zeek_digest,
                "Zeek-HMAC-Timestamp": self._test_ts,
            },
        )
        self.assertEqual(200, r.status_code)
        self.assertIn("job", r.json)

        self.assertEqual(
            self._test_build_hash, enqueue_job_mock.call_args[0][1]["build_hash"]
        )

    def test_zeek_bad_build_url(self, enqueue_job_mock):
        enqueue_job_mock.return_value = self.enqueue_job_result_mock

        r = self._test_client.post(
            "/zeek",
            query_string={
                "branch": "test-branch",
                "build": "http://example.com:8080/build.tgz",
                "build_hash": self._test_build_hash,
            },
            headers={
                "Zeek-HMAC": self._test_zeek_digest,
                "Zeek-HMAC-Timestamp": self._test_ts,
            },
        )
        self.assertEqual(400, r.status_code)
        self.assertIn("Invalid build URL", r.text)

        enqueue_job_mock.assert_not_called()

    def test_zeek_bad_hmac_digest(self, enqueue_job_mock):
        enqueue_job_mock.return_value = self.enqueue_job_result_mock

        r = self._test_client.post(
            "/zeek",
            query_string={
                "branch": "test-branch",
                "build": "http://localhost:8080/build.tgz",
                "build_hash": self._test_build_hash,
            },
            headers={
                "Zeek-HMAC": self._test_zeek_digest,
                "Zeek-HMAC-Timestamp": self._test_ts + 1,
            },
        )
        self.assertEqual(403, r.status_code)
        self.assertIn("HMAC validation failed", r.text)

        enqueue_job_mock.assert_not_called()

    def test_zeek_bad_branch(self, enqueue_job_mock):
        enqueue_job_mock.return_value = self.enqueue_job_result_mock

        r = self._test_client.post(
            "/zeek",
            query_string={
                "branch": "/test-branch//bad",
                "build": "http://localhost:8080/build.tgz",
                "build_hash": self._test_build_hash,
            },
            headers={
                "Zeek-HMAC": self._test_zeek_digest,
                "Zeek-HMAC-Timestamp": self._test_ts,
            },
        )
        self.assertEqual(400, r.status_code)
        self.assertIn("issing or invalid branch", r.text)


class TestBranchName(unittest.TestCase):
    def test_good(self):
        good_names = [
            "topic/jon/some-improvement",
            "topic/jon/1234-some-improvement",
            "topic/vern/ZAM-September-2023.09",
        ]
        for name in good_names:
            with self.subTest(name=name):
                self.assertTrue(is_valid_branch_name(name))

    def test_bad(self):
        bad_names = [
            "/topic/x",
            "@",
            "topic/.nope",
            "topic//nope/what",
            "topic/nope/what.lock",
            "topic/nope.lock/feature",
        ]

        for name in bad_names:
            with self.subTest(name, name=name):
                self.assertFalse(is_valid_branch_name(name))
