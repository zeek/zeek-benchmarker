import errno
import hashlib
import logging
import pathlib
import shutil
import subprocess
import typing
import dataclasses

import requests

from . import config, storage

logger = logging.getLogger(__name__)


def get_current_job_id():
    """
    Job ID as used by the queueing system.

    Within the rq worker, get_current_job() is valid.
    """
    import rq

    return rq.get_current_job().id


class Error(Exception):
    pass


class InvalidChecksum(Error):
    pass


Env = typing.Dict[str, str]


class ContainerRunner:
    """
    We have a curious docker-compose setup that restarts
    the same service with different environment variables.
    """

    def build_env(self, job: "Job", **kwargs) -> Env:
        env = {}

        cfg = config.get()

        env["BUILD_FILE_PATH"] = job.job_dir
        env["BUILD_FILE_NAME"] = job.build_filename
        env["ZEEKCPUS"] = cfg.zeek_cpus

        for k, v in kwargs.items():
            env[k] = v

        return env

    def run(self, target: str, env: Env, timeout: float = None):
        logger.debug("Running %s with %s", target, env)
        return subprocess.run(
            [
                "docker-compose",
                "up",
                "--no-log-prefix",
                "--force-recreate",
                target,
            ],
            env=env,
            # capture_output=True,
            stdout=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )


CONTAINER_RUNNER = ContainerRunner()


@dataclasses.dataclass
class Job:
    build_url: str
    build_hash: str

    original_branch: str
    normalized_branch: str
    commit: typing.Optional[str]

    # rq specific job_id
    job_id: str

    # build_hash rewritten
    sha256: str = None

    job_dir: pathlib.Path = None

    # Absolute path to downloaded file.
    build_path: str = None
    # Just the filename from build_path
    build_filename: str = None

    def fetch_build_url(self, build_path: pathlib.Path):
        """
        Download self.build_url into filename.
        """
        logger.debug("Downloading %s to %s", self.build_url, build_path)
        r = requests.get(
            self.build_url, allow_redirects=True, stream=True, timeout=(10, 300)
        )
        r.raise_for_status()

        # The file is being streamed, fetch it in chunks and compute sha256
        # on the fly.
        h = hashlib.sha256()
        with open(build_path, "wb") as fp:
            for chunk in r.iter_content(chunk_size=4096):
                h.update(chunk)
                fp.write(chunk)

        digest = h.digest().hex()
        if digest != self.sha256:
            raise InvalidChecksum(
                f"{self.build_url}: expected {self.sha256}, got {digest}"
            )

        # Consider unpacking of archive once into job_dir: It is currently
        # done over and over again for every test :-/

    def process(self):
        """
        Process this job.

        * Create the working directory
        * Fetch the artifact
        * Run _process()
        """
        try:
            self.job_dir.mkdir(parents=True)
        except OSError as e:
            if e.errno == errno.EEXIST:
                logger.warning("Job dir %s existed", self.job_dir)

        self.build_filename = pathlib.Path(self.build_url).parts[-1]
        self.build_path = self.job_dir / self.build_filename

        self.fetch_build_url(self.build_path)

        try:
            self._process()
            shutil.rmtree(self.job_dir)  # only cleanup on success for now
        except Exception as e:
            logger.error("Failed job %r", e)
            raise e

        def _process(self):
            """
            Implemented by subclasses.
            """
            raise NotImplementedError()


class ResultNotFound(Error):
    pass


class ZeekTestResult(typing.NamedTuple):
    test_run: int
    elapsed_time: float
    user_time: float
    system_time: float
    max_rss: float  # in bytes

    @staticmethod
    def parse_from(test_run: int, output: bytes):
        text = output.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if not line.startswith("BENCHMARK_TIMING="):
                continue

            values = line.split("=", 1)[1]
            elapsed_time, max_rss_kb, user_time, system_time = values.split(";")

            return ZeekTestResult(
                test_run=test_run,
                elapsed_time=float(elapsed_time),
                user_time=float(user_time),
                system_time=float(system_time),
                max_rss=int(max_rss_kb) * 1024,
            )

        raise ResultNotFound(text)


class ZeekTest(typing.NamedTuple):
    test_id: str
    runs: int
    pcap: str = None
    bench_command: str = None
    bench_args: str = None
    skip: bool = None

    @staticmethod
    def from_dict(d: typing.Dict[str, any]):
        return ZeekTest(
            test_id=d["id"],
            runs=d.get("runs", 3),
            bench_command=d.get("bench_command"),
            bench_args=d.get("bench_args"),
            pcap=d.get("pcap_file"),
            skip=d.get("skip", False),
        )


class ZeekJob(Job):
    def run_zeek_test(self, t):
        if t.skip:
            logger.warning("Skipping %s", t)
            return

        extra_env = {
            "BENCH_TEST_ID": t.test_id,
        }
        if t.bench_command and t.bench_args:
            extra_env["BENCH_COMMAND"] = t.bench_command
            extra_env["BENCH_ARGS"] = t.bench_args

        if t.pcap:
            extra_env["DATA_FILE_NAME"] = t.pcap

        env = CONTAINER_RUNNER.build_env(self, **extra_env)

        store = storage.get()
        for i in range(1, t.runs + 1):
            logger.debug("Running %s:%s (%d)", self.job_id, t.test_id, i)

            try:
                completed = CONTAINER_RUNNER.run("zeek-remote", env)
                result = ZeekTestResult.parse_from(i, completed.stdout)
                logger.info(
                    "Completed %s:%s (%d) result=%s", self.job_id, t.test_id, i, result
                )
                store.store_zeek_result(
                    job=self,
                    test=t,
                    result=result,
                )
            except ResultNotFound:
                logger.error("Missing result (%s) stdout=%s stderr=%s", completed.returncode, completed.stderr)
                return



    def _process(self):
        """ """
        cfg = config.get()
        for t in cfg["ZEEK_TESTS"]:
            zeek_test = ZeekTest.from_dict(t)
            self.run_zeek_test(zeek_test)


def zeek_job(req_vals):
    """
    Entry point for a Zeek job.
    """
    req_vals.pop("remote", None)  # consider everything a remote job.
    job = ZeekJob(job_id=get_current_job_id(), **req_vals)
    job.sha256 = job.build_hash

    cfg = config.get()
    job.job_dir = (pathlib.Path(cfg.work_dir) / get_current_job_id()).absolute()

    logger.info(
        "Working on job %s build_url=%s sha256=%s (jobdir=%s)",
        job.job_id,
        job.build_url,
        job.sha256,
        job.job_dir,
    )

    job.process()
