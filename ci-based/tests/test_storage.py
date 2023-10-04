"""
Smoke integration for faster testing of various pieces
"""
import sqlite3

from zeek_benchmarker import storage, testing
from zeek_benchmarker.models import Machine
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

    def make_test_machine(self, **kwargs):
        m = Machine(
            dmi_sys_vendor="LENOVO",
            dmi_product_uuid="test-product-uuid",
            dmi_product_serial="test-serial",
            dmi_board_asset_tag="test-asset-tag",
            os="Linux",
            architecture="x86_64",
            cpu_model="test-cpu-model",
            mem_total_bytes=16458768384,
        )
        for k, v in kwargs.items():
            setattr(m, k, v)
        return m

    def test_store_job(self):
        """
        Store a job in the database.
        """
        self.store.store_job(
            job_id="test-job-id",
            kind="zeek",
            machine_id=421234,
            req_vals={
                "build_url": "test-build-url",
                "build_hash": "test-build-hash",
                "sha": "test-sha",
                "commit": "test-sha",
                "branch": "test-branch",
                "original_branch": "test-original-branch",
                "cirrus_repo_owner": "test-cirrus-repo-owner",
                "cirrus_repo_name": "test-cirrus-repo-name",
                "cirrus_task_id": "test-cirrus-task-id",
                "cirrus_task_name": "test-cirrus-task-name",
                "cirrus_build_id": "test-cirrus-build-id",
                "cirrus_pr": "1111",
                "github_check_suite_id": "22334455",
                "repo_version": "test-repo-version",
            },
        )

        with sqlite3.connect(self.database_file.name) as conn:
            conn.row_factory = sqlite3.Row
            rows = list(conn.execute("select * from jobs"))

        # Just some smoke-checking
        self.assertEqual(1, len(rows))
        self.assertEqual(rows[0]["machine_id"], 421234)
        self.assertEqual(rows[0]["id"], "test-job-id")
        self.assertEqual(rows[0]["cirrus_pr"], 1111)
        self.assertEqual(rows[0]["github_check_suite_id"], 22334455)

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

    def test_get_or_create_machine(self):
        m1 = self.store.get_or_create_machine(self.make_test_machine())
        m2 = self.store.get_or_create_machine(self.make_test_machine())
        self.assertEqual(m1.id, m2.id)

        m3 = self.store.get_or_create_machine(
            self.make_test_machine(mem_total_bytes=12345678)
        )
        m4 = self.store.get_or_create_machine(
            self.make_test_machine(mem_total_bytes=12345678)
        )
        self.assertEqual(m3.id, m4.id)

        self.assertNotEqual(m1.id, m3.id)
