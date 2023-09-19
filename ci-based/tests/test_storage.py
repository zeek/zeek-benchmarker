"""
Smoke integration for faster testing of various pieces
"""
import sqlite3

from zeek_benchmarker import storage, testing
from zeek_benchmarker.tasks import ZeekJob, ZeekTest, ZeekTestResult


class TestStorage(testing.TestWithDatabase):
    def setUp(self):
        super().setUp()

        self.zeek_job = ZeekJob(
            job_id="test_job_id",
            build_url="test_build_url",
            build_hash="test_build_hash",
            original_branch="test_original_branch",
            normalized_branch="test_normalized_branch",
            commit="test_commit",
        )
        self.zeek_test = ZeekTest(test_id="test-id", runs=3)

        self.store = storage.Storage(self.database_file.name)

    def test_store_zeek_result(self):
        """
        Store a result in the database.
        """
        zeek_test_result = ZeekTestResult.parse_from(
            1, b"X\nBENCHMARK_TIMING=1.12;42;1.10;0.02\nX"
        )

        self.store.store_zeek_result(
            job=self.zeek_job,
            test=self.zeek_test,
            result=zeek_test_result,
        )

        with sqlite3.connect(self.database_file.name) as conn:
            conn.row_factory = sqlite3.Row
            rows = list(conn.execute("select * from zeek_tests"))
            self.assertEqual(1, len(rows))
            self.assertEqual(rows[0]["test_id"], "test-id")
            self.assertEqual(rows[0]["test_run"], 1)
            self.assertEqual(rows[0]["user_time"], 1.1)
            self.assertEqual(rows[0]["system_time"], 0.02)
            self.assertTrue(rows[0]["success"])
            self.assertIsNone(rows[0]["error"])

    def test_store_zeek_error(self):
        """
        Store a result in the database.
        """
        self.store.store_zeek_error(
            job=self.zeek_job,
            test=self.zeek_test,
            test_run=3,
            error="Something broke",
        )
        with sqlite3.connect(self.database_file.name) as conn:
            conn.row_factory = sqlite3.Row
            rows = list(conn.execute("select * from zeek_tests"))
            self.assertEqual(1, len(rows))
            self.assertEqual(rows[0]["test_id"], "test-id")
            self.assertEqual(rows[0]["test_run"], 3)
            self.assertFalse(rows[0]["success"])
            self.assertEqual(rows[0]["error"], "Something broke")
