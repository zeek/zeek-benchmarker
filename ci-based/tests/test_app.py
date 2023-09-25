import datetime
import hmac
import sqlite3
import time
import unittest
from unittest import mock

from zeek_benchmarker.app import create_app, is_valid_branch_name
from zeek_benchmarker.testing import TestWithDatabase


@mock.patch("zeek_benchmarker.app.enqueue_job")
class TestApi(TestWithDatabase):
    def setUp(self):
        super().setUp()
        self._test_hmac_key = b"test-key"

        self.app = create_app(
            config={
                "TESTING": True,
                "TEST": True,
                "ALLOWED_BUILD_URLS": ["http://localhost:8080/"],
                "HMAC_KEY": "test-key",
                "DATABASE_FILE": self.database_file.name,
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

    def test_zeek_good__more(self, enqueue_job_mock):
        enqueue_job_mock.return_value = self.enqueue_job_result_mock

        r = self._test_client.post(
            "/zeek",
            query_string={
                "branch": "test-branch",
                "build": "http://localhost:8080/build.tgz",
                "build_hash": self._test_build_hash,
                "commit": "f572d396fae9206628714fb2ce00f72e94f2258f",
                "cirrus_repo_owner": "test-owner",
                "cirrus_repo_name": "test-name",
                "cirrus_task_id": 123,
                "cirrus_task_name": "test-task-name",
                "cirrus_build_id": 9,
                "cirrus_pr": 456,
                "github_check_suite_id": 789,
                "repo_version": "6.1.0-dev.123",
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

        with sqlite3.connect(self.database_file.name) as conn:
            conn.row_factory = sqlite3.Row
            rows = list(conn.execute("select * from jobs"))
            self.assertEqual(1, len(rows))
            row = rows[0]
            self.assertEqual("zeek", row["kind"])
            self.assertEqual(self._test_build_hash, row["build_hash"])
            self.assertEqual("f572d396fae9206628714fb2ce00f72e94f2258f", row["sha"])
            self.assertEqual("test-branch", row["branch"])
            self.assertEqual("test-owner", row["cirrus_repo_owner"])
            self.assertEqual("test-name", row["cirrus_repo_name"])
            self.assertEqual(123, row["cirrus_task_id"])
            self.assertEqual("test-task-name", row["cirrus_task_name"])
            self.assertEqual(9, row["cirrus_build_id"])
            self.assertEqual(456, row["cirrus_pr"])
            self.assertEqual(789, row["github_check_suite_id"])
            self.assertEqual("6.1.0-dev.123", row["repo_version"])

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
        self.assertIn("Missing or invalid branch", r.text)


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
