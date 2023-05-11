import hmac
import os
import requests
import shutil
import subprocess
import sys
import time
import traceback
import sqlite3
import re
import io
import yaml
from datetime import datetime, timedelta

from flask import Flask, request

with open("config.yml") as config_file:
    try:
        config = yaml.safe_load(config_file)
    except yaml.YAMLError as exc:
        print(exc)
        sys.exit(1)

app = Flask(__name__)


def verify_hmac(request_path, timestamp, request_digest, build_hash):
    # Generate a new version of the digest on this side using the same information that the
    # caller use to generate their digest, and then compare the two for validity.
    hmac_msg = f"{request_path:s}-{timestamp:d}-{build_hash:s}\n"
    local_digest = hmac.new(
        config["HMAC_KEY"].encode("utf-8"), hmac_msg.encode("utf-8"), "sha256"
    ).hexdigest()
    if not hmac.compare_digest(local_digest, request_digest):
        app.logger.error(
            "HMAC digest from request ({:s}) didn't match local digest ({:s})".format(
                request_digest, local_digest
            )
        )
        return False

    return True


def parse_request(req):
    req_vals = {}
    branch = request.args.get("branch", "")
    if not branch:
        return "Branch argument required", 400

    build_url = request.args.get("build", None)
    if not build_url:
        return "Build argument required", 400

    # Validate that the build URL is either from Cirrus, or a local file from the local host.
    if build_url.startswith(
        "https://api.cirrus-ci.com/v1/artifact/build"
    ) or build_url.startswith("https://api.cirrus-ci.com/v1/artifact/task"):
        remote_build = True

        # Remote requests are required to be signed with HMAC and have an sha256 hash
        # of the build file passed with them.
        hmac_header = request.headers.get("Zeek-HMAC", None)
        if not hmac_header:
            return "HMAC header missing from request", 403

        hmac_timestamp = int(request.headers.get("Zeek-HMAC-Timestamp", 0))
        if not hmac_timestamp:
            return "HMAC timestamp missing from request", 403

        # Double check that the timestamp is within the last 15 minutes UTC to avoid someone
        # trying to reuse it.
        ts = datetime.utcfromtimestamp(hmac_timestamp)
        utc = datetime.utcnow()
        delta = utc - ts

        if delta > timedelta(minutes=15):
            return "HMAC timestamp is outside of the valid range", 403

        req_vals["build_hash"] = request.args.get("build_hash", "")
        if not req_vals["build_hash"]:
            return "Build hash argument required", 400

        if not verify_hmac(
            request.path, hmac_timestamp, hmac_header, req_vals["build_hash"]
        ):
            return "HMAC validation failed", 403

    elif build_url.startswith("file://") and request.remote_addr == "127.0.0.1":
        remote_build = False
    else:
        return "Invalid build URL", 400

    # Validate the branch name. Disallow semi-colon and then use git's
    # method for testing for valid names.
    if ";" in branch:
        return "Invalid branch name", 400

    ret = subprocess.call(
        ["git", "check-ref-format", "--branch", branch], stdout=subprocess.DEVNULL
    )
    if ret:
        return "Invalid branch name", 400

    # Normalize the branch name to remove any non-alphanumeric characters so it's
    # safe to use as part of a path name. This is way overkill, but it's safer.
    # Docker requires it to be all lowercase as well.
    normalized_branch = "".join(x for x in branch if x.isalnum()).lower()
    if remote_build:
        normalized_branch += f"-{int(hmac_timestamp):d}-{int(time.time()):d}"
    else:
        normalized_branch += f"-local-{int(time.time()):d}"

    req_vals["build_url"] = build_url
    req_vals["remote"] = remote_build
    req_vals["normalized_branch"] = normalized_branch
    req_vals["commit"] = request.args.get("commit", "")
    return req_vals


def build_docker_env(target, config, req_vals, work_path, filename):
    docker_env = {
        "DATA_FILE_NAME": config["DATA_FILE"],
        "BUILD_FILE_NAME": "",
        "BUILD_FILE_PATH": "",
    }

    if req_vals["remote"]:
        docker_image = f"{target}-remote"
        file_path = os.path.join(work_path, filename)
        r = requests.get(req_vals["build_url"], allow_redirects=True)
        if not r:
            raise RuntimeError("Failed to download build file")

        open(file_path, "wb").write(r.content)
        open(f"{file_path:s}.sha256", "w").write(
            "{:s} {:s}".format(req_vals["build_hash"], file_path)
        )

        # Validate checksum of file before untarring it. There is a module in python
        # to do this, but I'm not going to read the whole file into memory to do it.
        ret = subprocess.call(
            ["sha256sum", "-c", f"{file_path:s}.sha256"],
            stdout=subprocess.DEVNULL,
        )
        if ret:
            raise RuntimeError("Failed to validate build file checksum")

        docker_env["BUILD_FILE_PATH"] = work_path
        docker_env["BUILD_FILE_NAME"] = filename
    else:
        docker_image = f"{target}-local"
        docker_env["BUILD_FILE_PATH"] = req_vals["build_url"][7:]

    return (docker_image, docker_env)


@app.route("/zeek", methods=["POST"])
def zeek():
    req_vals = parse_request(request)
    if not isinstance(req_vals, dict):
        return req_vals

    base_path = os.path.dirname(os.path.abspath(__file__))
    work_path = os.path.join(base_path, req_vals["normalized_branch"])

    filename = req_vals["build_url"].rsplit("/", 1)[1]

    result = None
    try:
        os.mkdir(work_path, mode=0o700)

        (docker_image, docker_env) = build_docker_env(
            "zeek", config, req_vals, work_path, filename
        )
        docker_env["ZEEKCPUS"] = ",".join(map(str, config["CPU_SET"]))

        total_time = 0
        total_mem = 0

        for i in range(config["RUN_COUNT"]):
            proc = subprocess.Popen(
                [
                    "/usr/bin/docker-compose",
                    "up",
                    "--no-log-prefix",
                    "--force-recreate",
                    docker_image,
                ],
                env=docker_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if not proc:
                raise RuntimeError("Runner failed to execute")

            found = False
            for line in io.TextIOWrapper(proc.stdout, encoding="utf-8"):
                match = re.match(r"(\d+(\.\d+)?) (\d+)", line)
                if match:
                    total_time += float(match.group(1))
                    total_mem += int(match.group(3))
                    found = True
                    break

            if not found:
                raise RuntimeError(f"Failed to find valid output in pass {i:d}")

        avg_time = total_time / float(config["RUN_COUNT"])
        avg_mem = int(total_mem / float(config["RUN_COUNT"]))
        log_output = """Averaged over {:d} passes:\n
                        Time Spent: {:.3f} seconds\n
                        Max memory usage: {:d} bytes""".format(
            config["RUN_COUNT"], avg_time, avg_mem
        )

        if req_vals["remote"]:
            db_conn = sqlite3.connect(config["DATABASE_FILE"])
            c = db_conn.cursor()
            c.execute(
                """CREATE TABLE IF NOT EXISTS "zeek" (
                       "id" integer primary key autoincrement not null,
                       "stamp" datetime default (datetime('now', 'localtime')),
                       "time_spent" float not null,
                       "memory_used" float not null, "sha" text, "branch" text);"""
            )

            c.execute(
                "insert into zeek (time_spent, memory_used, sha) values (?,?,?)",
                [
                    avg_time,
                    avg_mem,
                    req_vals.get("commit", ""),
                    req_vals("normalized_branch", ""),
                ],
            )
            db_conn.commit()
            db_conn.close()

    except RuntimeError as rt_err:
        app.logger.error(traceback.format_exc())
        result = (str(rt_err), 500)
    except Exception:
        # log any other exceptions, but eat the string from them
        app.logger.error(traceback.format_exc())
        result = ("Failure occurred", 500)
    else:
        result = (log_output, 200)

    subprocess.call(["docker", "container", "rm", "zeek"])

    if os.path.exists(work_path):
        shutil.rmtree(work_path)

    return result


@app.route("/broker", methods=["POST"])
def broker():
    req_vals = parse_request(request)
    if not isinstance(req_vals, dict):
        return req_vals

    base_path = os.path.dirname(os.path.abspath(__file__))
    work_path = os.path.join(base_path, req_vals["normalized_branch"])
    filename = req_vals["build_url"].rsplit("/", 1)[1]

    result = None
    try:
        os.mkdir(work_path, mode=0o700)

        (docker_image, docker_env) = build_docker_env(
            "broker", config, req_vals, work_path, filename
        )

        # Run benchmark
        proc = subprocess.Popen(
            [
                "/usr/bin/docker-compose",
                "up",
                "--no-log-prefix",
                "--force-recreate",
                docker_image,
            ],
            env=docker_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if not proc:
            raise RuntimeError("Runner failed to execute")
        if not proc.stdout:
            raise RuntimeError("stdout was missing")

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

        if req_vals["remote"]:
            db_conn = sqlite3.connect(config["DATABASE_FILE"])
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
                       system, sha) values (?,?,?,?,?,?,?,?,?,?)""",
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
                    req_vals["commit"],
                    req_vals["normalized_branch"],
                ],
            )

            db_conn.commit()
            db_conn.close()

    except RuntimeError as rt_err:
        app.logger.error(traceback.format_exc())
        result = (str(rt_err), 500)
    except Exception:
        # log any other exceptions, but eat the string from them
        app.logger.error(traceback.format_exc())
        result = ("Failure occurred", 500)
    else:
        result = (log_output, 200)

    subprocess.call(["docker", "container", "rm", "broker"])

    if os.path.exists(work_path):
        shutil.rmtree(work_path)

    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=False)
