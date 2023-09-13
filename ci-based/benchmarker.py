import hashlib
import hmac
import io
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import traceback
from datetime import datetime, timedelta

import redis
import requests
import rq
import yaml
import zeek_benchmarker.tasks
from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden

with open("config.yml") as config_file:
    try:
        config = yaml.safe_load(config_file)
    except yaml.YAMLError as exc:
        print(exc)
        sys.exit(1)

app = Flask(__name__)


def is_allowed_build_url_prefix(url):
    """
    Is the given url a prefix in ALLOWED_BUILD_URLS
    """
    return any(url.startswith(allowed) for allowed in config["ALLOWED_BUILD_URLS"])


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


def check_hmac_request(req):
    """
    Remote requests are required to be signed with HMAC and have an sha256 hash
    of the build file passed with them.
    """
    hmac_header = req.headers.get("Zeek-HMAC", None)
    if not hmac_header:
        raise Forbidden("HMAC header missing from request")

    hmac_timestamp = int(req.headers.get("Zeek-HMAC-Timestamp", 0))
    if not hmac_timestamp:
        raise Forbidden("HMAC timestamp missing from request")

    # Double check that the timestamp is within the last 15 minutes UTC to avoid someone
    # trying to reuse it.
    ts = datetime.utcfromtimestamp(hmac_timestamp)
    utc = datetime.utcnow()
    delta = utc - ts

    if delta > timedelta(minutes=15):
        raise Forbidden("HMAC timestamp is outside of the valid range")

    build_hash = req.args.get("build_hash", "")
    if not build_hash:
        raise BadRequest("Build hash argument required")

    if not verify_hmac(req.path, hmac_timestamp, hmac_header, build_hash):
        raise Forbidden("HMAC validation failed")


def parse_request(req):
    req_vals = {}
    branch = request.args.get("branch", "")
    if not branch:
        raise BadRequest("Branch argument required")

    build_url = request.args.get("build", None)
    if not build_url:
        raise BadRequest("Build argument required")

    req_vals["build_hash"] = request.args.get("build_hash", "")

    # Validate that the build URL is allowed via the config, or local file from the local host.
    if is_allowed_build_url_prefix(build_url):
        check_hmac_request(request)
        remote_build = True
    elif build_url.startswith("file://") and request.remote_addr == "127.0.0.1":
        remote_build = False
    else:
        raise BadRequest("Invalid build URL")

    # Validate the branch name. Disallow semi-colon and then use git's
    # method for testing for valid names.
    if ";" in branch:
        raise BadRequest("Invalid branch name")

    ret = subprocess.call(
        ["git", "check-ref-format", "--branch", branch], stdout=subprocess.DEVNULL
    )
    if ret:
        raise BadRequest("Invalid branch name")

    # Normalize the branch name to remove any non-alphanumeric characters so it's
    # safe to use as part of a path name. This is way overkill, but it's safer.
    # Docker requires it to be all lowercase as well.
    hmac_timestamp = int(req.headers.get("Zeek-HMAC-Timestamp", 0))
    req_vals["original_branch"] = "".join(x for x in branch if x.isalnum()).lower()
    normalized_branch = req_vals["original_branch"]
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
        r = requests.get(req_vals["build_url"], allow_redirects=True, stream=True)
        if not r.ok:
            raise RuntimeError(f"Failed to download build file: {r.status_code}")

        # Fetch the file in chunks and compute sha256 while we do so
        h = hashlib.sha256()
        with open(file_path, "wb") as fp:
            for chunk in r.iter_content(chunk_size=4096):
                h.update(chunk)
                fp.write(chunk)

        digest = h.digest().hex()
        app.logger.info("Downloaded %s with sha256 %s", req_vals["build_url"], digest)

        if req_vals["build_hash"] != digest:
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

    # At this point we've validated the request and just
    # enqueue it for the worker to pick up.
    redis_host = os.getenv("REDIS_HOST", "localhost")
    queue_name = os.getenv("RQ_QUEUE_NAME", "default")

    # New connection per request, that's alright for now.
    with redis.Redis(host=redis_host) as redis_conn:
        q = rq.Queue(name=queue_name, connection=redis_conn)
        job = q.enqueue(zeek_benchmarker.tasks.zeek_job, req_vals)

        return jsonify(
            {
                "job": {
                    "id": job.id,
                    "enqueued_at": job.enqueued_at,
                }
            }
        )


@app.route("/broker", methods=["POST"])
def broker():
    req_vals = parse_request(request)
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
                    req_vals.get("commit", ""),
                    req_vals.get("original_branch", ""),
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
