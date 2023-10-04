"""
Tiny storage abstraction.

Really using sqlite directly, but this allows to test it some.
"""
import sqlite3

import sqlalchemy as sa

from . import config, models


def get_engine(url: str) -> sa.Engine:
    """
    Get an SQLAlchemy engine:
    """
    if "://" not in url:
        url = f"sqlite:///{url}"
    return sa.create_engine(url)


class Storage:
    def __init__(self, filename):
        self._filename = filename
        self.Session = sa.orm.sessionmaker(get_engine(self._filename))

    def store_job(
        self,
        *,
        job_id: str,
        kind: str,
        machine_id: int,
        req_vals: dict[str, any],
    ):
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
                         cirrus_task_name,
                         cirrus_build_id,
                         cirrus_pr,
                         github_check_suite_id,
                         repo_version,
                         machine_id
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
                        :cirrus_task_name,
                        :cirrus_build_id,
                        :cirrus_pr,
                        :github_check_suite_id,
                        :repo_version,
                        :machine_id
                    )"""
            data = req_vals.copy()
            data["id"] = job_id
            data["sha"] = req_vals["commit"]
            data["kind"] = kind
            data["machine_id"] = machine_id
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

    def get_or_create_machine(self, m: models.Machine):
        """
        Find an entry in table machine with all the same attributes and
        return it, or insert the new information and return that entry.

        There might be a better way, but we do want to check that all
        the columns are the same. The following is a bit more generic
        in case we need that: https://stackoverflow.com/a/6078058
        """
        with self.Session() as session:
            # Allow access to the returned objects after returning
            # from this function.
            session.expire_on_commit = False

            query = session.query(models.Machine).where(
                models.Machine.dmi_sys_vendor == m.dmi_sys_vendor,
                models.Machine.dmi_product_uuid == m.dmi_product_uuid,
                models.Machine.dmi_product_serial == m.dmi_product_serial,
                models.Machine.dmi_board_asset_tag == m.dmi_board_asset_tag,
                models.Machine.os == m.os,
                models.Machine.architecture == m.architecture,
                models.Machine.cpu_model == m.cpu_model,
                models.Machine.mem_total_bytes == m.mem_total_bytes,
            )

            r = query.scalar()
            if r:
                return r

            session.add(m)
            session.commit()
            session.expunge(m)
            return m


_storage = None


def get() -> Storage:
    """
    Get a singleton Storage handle.
    """
    global _storage
    if _storage is None:
        _storage = Storage(config.get()["DATABASE_FILE"])

    return _storage
