"""
Smoke integration for faster testing of various pieces
"""
import sqlite3

from zeek_benchmarker import storage, testing
from zeek_benchmarker.tasks import ZeekJob, ZeekTest, ZeekTestResult


class TestStorage(testing.TestWithDatabase):
    def test_storage_smoke(self):
        """
        Store a result in the database.
        """
        zeek_job = ZeekJob(
            job_id="test_job_id",
            build_url="test_build_url",
            build_hash="test_build_hash",
            original_branch="test_original_branch",
            normalized_branch="test_normalized_branch",
            commit="test_commit",
        )
        zeek_test = ZeekTest(test_id="test-id", runs=3)
        zeek_test_result = ZeekTestResult.parse_from(
            1, b"X\nBENCHMARK_TIMING=1.12;42;1.10;0.02\nX"
        )

        store = storage.Storage(self.database_file.name)

        store.store_zeek_result(
            job=zeek_job,
            test=zeek_test,
            result=zeek_test_result,
        )

        with sqlite3.connect(self.database_file.name) as conn:
            conn.row_factory = sqlite3.Row
            rows = list(conn.execute("select * from zeek_tests"))
            self.assertEqual(1, len(rows))
            self.assertEqual(rows[0]["test_id"], "test-id")
            self.assertEqual(rows[0]["user_time"], 1.1)
            self.assertEqual(rows[0]["system_time"], 0.02)
            self.assertTrue(rows[0]["success"])
            self.assertIsNone(rows[0]["error"])
