import dataclasses
import errno
import hashlib
import json
import logging
import os
import os.path
import pathlib
import re
import shlex
import shutil
import typing

import docker
import docker.types
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


class CommandFailed(Error):
    """Raised when the command within the container has a non-zero exit status."""

    pass


Env = dict[str, str]


class ContainerRunner:
    """
    We have a curious docker-compose setup that restarts
    the same service with different environment variables.
    """

    _instance: typing.Optional["ContainerRunner"] = None

    @staticmethod
    def get() -> "ContainerRunner":
        if ContainerRunner._instance is None:
            ContainerRunner._instance = ContainerRunner()

        return ContainerRunner._instance

    def __init__(self, client: docker.client.DockerClient = None):
        self._client = client or docker.from_env()

    def runc(
        self,
        *,
        image: str,
        command: str,
        env: Env,
        seccomp_profile: dict[str, typing.Any],  # contents of the seccomp profile
        install_volume: str,
        install_target: str,
        test_data_volume: str,
        test_data_target: str = "/test_data",
        cap_add: list[str] | None = None,
        network_disabled: bool = True,
    ):
        """
        Run the given image for benchmarking, mounting
        install_volume at install_target.
        """
        # Don't modify the caller's env.
        env = env.copy()

        # Ensure the image exists locally.
        self._client.images.get(image)

        class Result(typing.NamedTuple):
            returncode: int
            stdout: bytes
            stderr: bytes

        cap_add = cap_add or ["SYS_NICE"]
        default_tmpfs_path = "/mnt/data/tmpfs"
        default_run_path = "/run"
        tmpfs = {
            default_tmpfs_path: "",
            default_run_path: "",
        }

        env["TMPFS_PATH"] = default_tmpfs_path
        env["RUN_PATH"] = default_run_path

        mounts = [
            docker.types.Mount(
                type="volume",
                source=install_volume,
                target=install_target,
            ),
            docker.types.Mount(
                type="volume",
                source=test_data_volume,
                target=test_data_target,
            ),
        ]

        security_opt = [
            f"seccomp={json.dumps(seccomp_profile)}",
        ]

        container = self._client.containers.run(
            image=image,
            working_dir=default_run_path,
            command=command,
            detach=True,
            cap_add=cap_add,
            environment=env,
            tmpfs=tmpfs,
            mounts=mounts,
            security_opt=security_opt,
            network_disabled=network_disabled,
        )

        try:
            wait = container.wait()
            stdout_bytes = container.logs(stdout=True, stderr=False)
            stderr_bytes = container.logs(stdout=False, stderr=True)
            result = Result(wait.get("StatusCode", 99), stdout_bytes, stderr_bytes)
            logger.debug(
                "runc: returndcode=%s stdout=%s stderr=%s",
                result.returncode,
                result.stdout,
                result.stderr,
            )

            if result.returncode:
                raise CommandFailed(result)

            return result
        finally:
            container.remove(force=True)

    def unpack_build(
        self,
        *,
        build_path: pathlib.Path,
        image: str,
        volume: str,
        strip_components=2,
        timeout=30,
    ):
        """
        Starts a container and extracts the tar archive provided by
        ``build_path`` into ``volume`` using ``image``.

        The contents of ``volume`` are deleted before extraction.
        """
        if not build_path.exists():
            raise FileNotFoundError(str(build_path))

        # Expected: /dir/<job-id>/build.tgz
        if len(build_path.parts) < 3:
            raise ValueError(str(build_path))

        if not volume:
            raise ValueError("no volume")

        # Where to extract into in the container.
        target_dir = "/target"
        # Where to mount the directory where build.tgz is located into.
        source_dir = "/source"

        # This will be job-id/build.tgz.
        build_filename = os.path.sep.join(build_path.parts[-2:])

        command = " ".join(
            [
                f"rm -rf {shlex.quote(target_dir)}/{{*,.*}};",
                f"timeout --signal=SIGKILL {int(timeout)}",
                f"tar -xzf {shlex.quote(build_filename)}",
                f"--strip-components {int(strip_components)}",
                f"-C {shlex.quote(target_dir)}",
            ]
        )

        mounts = [
            docker.types.Mount(
                target=target_dir,
                source=volume,
            ),
        ]

        # If the spool directory is backed by a volume (when this code
        # is running within docker-compose), need to use a volume mount
        # because the paths within the container are meaningless to the
        # docker daemon running on the host for bind-mounts.
        spool_volume = os.getenv("SPOOL_VOLUME")
        if spool_volume:
            source_mount = docker.types.Mount(
                read_only=True,
                target=source_dir,
                source=spool_volume,
                type="volume",
            )
        else:
            spool_dir = str(build_path.parent.parent)
            source_mount = docker.types.Mount(
                read_only=True,
                target=source_dir,
                source=spool_dir,
                type="bind",
            )

        mounts.append(source_mount)

        logger.debug("Unpacking %s in container: %s (%s)", build_path, command, mounts)
        self._client.containers.run(
            image=image,
            mounts=mounts,
            auto_remove=True,
            network_disabled=True,
            working_dir=source_dir,
            security_opt=["no-new-privileges"],
            command=["bash", "-x", "-c", command],
        )


@dataclasses.dataclass
class Job:
    build_url: str
    build_hash: str

    original_branch: str
    normalized_branch: str
    commit: str | None

    # rq specific job_id
    job_id: str

    # build_hash rewritten
    sha256: str | None = None

    job_dir: pathlib.Path | None = None

    # Absolute path to downloaded file.
    build_path: str | None = None
    # Just the filename from build_path
    build_filename: str | None = None

    # This is the actual original branch
    # name as submitted through the API.
    branch: str | None = None

    # Extra information from the API
    cirrus_repo_owner: str | None = None
    cirrus_repo_name: str | None = None
    cirrus_task_id: int | None = None
    cirrus_task_name: str | None = None
    cirrus_build_id: int | None = None
    cirrus_pr: int | None = None
    cirrus_pr_labels: str | None = None
    github_check_suite_id: int | None = None
    repo_version: str | None = None

    @property
    def install_volume(self) -> str:
        """
        Volume into which to extract build_path into the
        testing container.
        """
        raise NotImplementedError()

    @property
    def testing_image(self) -> str:
        """
        Image used for unpacking and running benchmarking tests.
        """
        raise NotImplementedError()

    @property
    def unpack_strip_component(self) -> int:
        """
        How many components to strip when running tar on build.tgz
        """
        return 2

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

        cr = ContainerRunner.get()

        cr.unpack_build(
            build_path=self.build_path,
            image=self.testing_image,
            volume=self.install_volume,
            strip_components=self.unpack_strip_component,
            timeout=config.get().tar_timeout,
        )

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
    pcap: str | None = None
    pcap_args: str | None = None
    bench_command: str | None = None
    bench_args: str | None = None
    skip: bool | None = None

    @staticmethod
    def from_dict(cfg: config.Config, d: dict[str, typing.Any]):
        return ZeekTest(
            test_id=d["id"],
            runs=d.get("runs", cfg.run_count),
            bench_command=d.get("bench_command"),
            bench_args=d.get("bench_args"),
            pcap=d.get("pcap_file"),
            pcap_args=d.get("pcap_args"),
            skip=d.get("skip", False),
        )


class ZeekJob(Job):
    """
    Zeek benchmarker job.
    """

    @property
    def install_volume(self) -> str:
        return "zeek_install_data"

    @property
    def testing_image(self) -> str:
        return "zeek-benchmarker-zeek-runner"

    def run_zeek_test(self, t):
        if t.skip:
            logger.warning("Skipping %s", t)
            return

        cr = ContainerRunner.get()
        cfg = config.get()

        env = {
            "BENCH_TEST_ID": t.test_id,
            "ZEEKCPUS": cfg.zeek_cpus,
            "ZEEKBIN": "/zeek/install/bin/zeek",
            "ZEEKSEED": "/benchmarker/random.seed",
        }

        if t.bench_command:
            env["BENCH_COMMAND"] = t.bench_command

        if t.bench_args:
            env["BENCH_ARGS"] = t.bench_args

        if t.pcap:
            env["DATA_FILE_NAME"] = t.pcap

        if t.pcap_args:
            env["PCAP_ARGS"] = t.pcap_args

        # TODO: Make configurable.
        with open("./zeek-seccomp.json", "rb") as fp:
            seccomp_profile = json.load(fp)

        store = storage.get()
        for i in range(1, t.runs + 1):
            logger.debug("Running %s:%s (%d)", self.job_id, t.test_id, i)

            try:
                proc = cr.runc(
                    image=self.testing_image,
                    command="/benchmarker/scripts/run-zeek.sh",
                    env=env,
                    seccomp_profile=seccomp_profile,
                    install_volume=self.install_volume,
                    install_target="/zeek/install",
                    test_data_volume="test_data",
                )

                result = ZeekTestResult.parse_from(i, proc.stdout)
                logger.info(
                    "Completed %s:%s (%d) result=%s", self.job_id, t.test_id, i, result
                )
                store.store_zeek_result(
                    job=self,
                    test=t,
                    result=result,
                )
            except ResultNotFound:
                error = (
                    f"Missing result {proc.returncode} "
                    f"stdout={proc.stdout} stderr={proc.stderr}"
                )
                logger.error(error)
                store.store_zeek_error(job=self, test=t, test_run=i, error=error)
            except Exception as e:
                error = f"Unhandled exception {type(e)} {e}"
                logger.exception(error)
                store.store_zeek_error(job=self, test=t, test_run=i, error=error)

    def _process(self):
        cfg = config.get()
        for t in cfg.zeek_tests:
            zeek_test = ZeekTest.from_dict(cfg, t)
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


class BrokerJob(Job):
    """
    Broker benchmarker job.
    """

    @property
    def install_volume(self) -> str:
        """
        XXX: This needs testing.
        """
        return "broker_install_data"

    @property
    def testing_image(self) -> str:
        return "zeek-benchmarker-broker-runner"

    def _process(self):
        import io
        import sqlite3

        raise NotImplementedError("XXX this needs a re-work")

        cr = ContainerRunner.get()
        env = cr.build_env(self)
        proc = cr.run("broker-remote", env)

        # Original code from benchmarker.py. 2023-09-14, no test data.
        # Not sure this still works.
        log_output = ""
        log_data = {}
        p = re.compile(r"zeek-recording-(.*?) \((.*?)\): (.*)s")
        for line in io.TextIOWrapper(proc.stdout, encoding="utf-8"):
            if line.startswith("system"):
                log_output += line
                parts = line.split(":")
                log_data["system"] = float(parts[1].strip()[:-1])
            elif line.startswith("zeek"):
                log_output += line
                m = p.match(line)
                if m:
                    log_data[f"{m.group(1):s}_{m.group(2):s}"] = float(m.group(3))

            cfg = config.get()
            with sqlite3.connect(cfg["DATABASE_FILE"]) as db_conn:
                c = db_conn.cursor()
                c.execute(
                    """CREATE TABLE IF NOT EXISTS "broker" (
                           "stamp" datetime primary key default (datetime('now', 'localtime')),
                           "logger_sending" float not null,
                           "logger_receiving" float not null,
                           "manager_sending" float not null,
                           "manager_receiving" float not null,
                           "proxy_sending" float not null,
                           "proxy_receiving" float not null,
                           "worker_sending" float not null,
                           "worker_receiving" float not null,
                           "system" float not null, "sha" text, "branch" text);"""
                )

                c.execute(
                    """insert into broker (logger_sending, logger_receiving,
                           manager_sending, manager_receiving,
                           proxy_sending, proxy_receiving,
                           worker_sending, worker_receiving,
                           system, sha, branch) values (?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        log_data["logger_sending"],
                        log_data["logger_receiving"],
                        log_data["manager_sending"],
                        log_data["manager_receiving"],
                        log_data["proxy_sending"],
                        log_data["proxy_receiving"],
                        log_data["worker_sending"],
                        log_data["worker_receiving"],
                        log_data["system"],
                        self.commit or "",
                        self.original_branch,
                    ],
                )

                db_conn.commit()
                db_conn.close()


def broker_job(req_vals):
    """
    Entry point for a Broker job.
    """
    req_vals.pop("remote", None)  # consider everything a remote job.
    job = BrokerJob(job_id=get_current_job_id(), **req_vals)
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
