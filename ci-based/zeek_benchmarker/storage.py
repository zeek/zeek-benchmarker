"""
Tiny storage abstraction.

Really using sqlite directly, but this allows to test it some.
"""
import sqlite3

from . import config


class Storage:
    def __init__(self, filename):
        self._filename = filename

    def store_job(self, *, job_id: str, kind: str, req_vals: dict[any, any]):
        with sqlite3.connect(self._filename) as conn:
            c = conn.cursor()
            sql = """INSERT INTO jobs (
                         id,
                         kind,
                         build_url,
                         build_hash,
                         sha,
                         branch,
                         original_branch,
                         cirrus_repo_owner,
                         cirrus_repo_name,
                         cirrus_task_id,
                         cirrus_build_id,
                         cirrus_pr,
                         github_check_suite_id,
                         repo_version
                    ) VALUES (
                        :id,
                        :kind,
                        :build_url,
                        :build_hash,
                        :sha,
                        :branch,
                        :original_branch,
                        :cirrus_repo_owner,
                        :cirrus_repo_name,
                        :cirrus_task_id,
                        :cirrus_build_id,
                        :cirrus_pr,
                        :github_check_suite_id,
                        :repo_version
                    )"""
            data = req_vals.copy()
            data["id"] = job_id
            data["sha"] = req_vals["commit"]
            data["kind"] = kind
            c.execute(sql, data)

    def store_zeek_result(
        self,
        *,
        job: "zeek_benchmarker.tasks.ZeekJob",  # noqa: F821
        test: "zeek_benchmarker.tasks.ZeekTest",  # noqa: F821
        result: "zeek_benchmarker.tasks.ZeekTestResult",  # noqa: F821
    ):
        """
        Store a results entry into the zeek_tests table.
        """
        with sqlite3.connect(self._filename) as conn:
            c = conn.cursor()
            sql = """INSERT INTO zeek_tests (
                         job_id,
                         test_id,
                         test_run,
                         elapsed_time,
                         user_time,
                         system_time,
                         max_rss,
                         sha,
                         branch,
                         success
                    ) VALUES (
                        :job_id,
                        :test_id,
                        :test_run,
                        :elapsed_time,
                        :user_time,
                        :system_time,
                        :max_rss,
                        :sha,
                        :branch,
                        :success
                    )"""
            data = result._asdict()
            data["job_id"] = job.job_id
            data["sha"] = job.commit
            data["branch"] = job.original_branch
            data["test_id"] = test.test_id
            data["success"] = True
            c.execute(sql, data)

    def store_zeek_error(
        self,
        *,
        job: "zeek_benchmarker.tasks.ZeekJob",  # noqa: F821
        test: "zeek_benchmarker.tasks.ZeekTest",  # noqa: F821
        test_run: int,
        error: str,
    ):
        """
        Set success=False and store the error message.
        """
        with sqlite3.connect(self._filename) as conn:
            c = conn.cursor()
            sql = """INSERT INTO zeek_tests (
                         job_id,
                         test_id,
                         test_run,
                         sha,
                         branch,
                         success,
                         error
                    ) VALUES (
                        :job_id,
                        :test_id,
                        :test_run,
                        :sha,
                        :branch,
                        :success,
                        :error
                    )"""

            data = {
                "job_id": job.job_id,
                "sha": job.commit,
                "branch": job.original_branch,
                "test_id": test.test_id,
                "test_run": test_run,
                "success": False,
                "error": error,
            }
            c.execute(sql, data)


def get() -> Storage:
    """
    Get a Storage handle.
    """
    return Storage(config.get()["DATABASE_FILE"])
