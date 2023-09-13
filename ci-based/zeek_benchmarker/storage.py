"""
Tiny storage abstraction.

Really using sqlite directly, but this allows to test it some.
"""
import sqlite3

from . import config


class Storage:
    def __init__(self, filename):
        self._filename = filename

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
            c.execute(
                """CREATE TABLE IF NOT EXISTS "zeek_tests" (
                       "id" integer primary key autoincrement not null,
                       "ts" datetime default (UNIXEPOCH()),
                       "stamp" datetime default (datetime('now', 'localtime')),
                       "job_id" text not null,
                       "test_id" text not null,
                       "test_run" integer not null,
                       "elapsed_time" float not null,
                       "user_time" float not null,
                       "system_time" float not null,
                       "max_rss" float not null,
                       "sha" text,
                       "branch" text);"""
            )

            sql = """INSERT INTO zeek_tests (
                         job_id,
                         test_id,
                         test_run,
                         elapsed_time,
                         user_time,
                         system_time,
                         max_rss,
                         sha,
                         branch
                    ) VALUES (
                        :job_id,
                        :test_id,
                        :test_run,
                        :elapsed_time,
                        :user_time,
                        :system_time,
                        :max_rss,
                        :sha,
                        :branch
                    )"""
            data = result._asdict()
            data["job_id"] = job.job_id
            data["sha"] = job.commit
            data["branch"] = job.original_branch
            data["test_id"] = test.test_id
            c.execute(sql, data)


def get() -> Storage:
    """
    Get a Storage handle.
    """
    return Storage(config.get()["DATABASE_FILE"])
