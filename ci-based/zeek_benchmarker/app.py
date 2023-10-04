import hmac
import os
import time
from datetime import datetime, timedelta

import redis
import rq
import zeek_benchmarker.machine
import zeek_benchmarker.tasks
from flask import Flask, current_app, jsonify, request
from werkzeug.exceptions import BadRequest, Forbidden
from zeek_benchmarker import storage


def is_allowed_build_url_prefix(url):
    """
    Is the given url a prefix in ALLOWED_BUILD_URLS
    """
    allowed_build_urls = current_app.config["ALLOWED_BUILD_URLS"]
    return any(url.startswith(allowed) for allowed in allowed_build_urls)


def verify_hmac(request_path, timestamp, request_digest, build_hash):
    # Generate a new version of the digest on this side using the same information that the
    # caller use to generate their digest, and then compare the two for validity.
    hmac_msg = f"{request_path:s}-{timestamp:d}-{build_hash:s}\n".encode()
    hmac_key = current_app.config["HMAC_KEY"].encode("utf-8")
    local_digest = hmac.new(hmac_key, hmac_msg, "sha256").hexdigest()
    if not hmac.compare_digest(local_digest, request_digest):
        current_app.logger.error(
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


def is_valid_branch_name(branch: str):
    """
    Check if this is a valid branch name. Typing out the rules in the manpage.
    We normalize it anyhow, so not sure this is needed.
    """
    if not branch:
        return False

    # Arbitrary
    if len(branch) > 256:
        return False

    disallowed = [";", "/.", "..", "~", "^", ":", "*", "?", "[", "//", "@{", "\\"]
    for d in disallowed:
        if d in branch:
            return False

    if branch.startswith("/") or branch.endswith(".") or branch == "@":
        return False

    parts = branch.split("/")
    if any(p.endswith(".lock") for p in parts):
        return False

    return True


def parse_request(req):
    """
    Generic request parsing.
    """
    req_vals = {}

    branch = request.args.get("branch", "")
    if not is_valid_branch_name(branch):
        raise BadRequest("Missing or invalid branch")

    req_vals["branch"] = branch

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

    # These values are mostly relevant for the jobs table.
    req_vals["cirrus_repo_owner"] = request.args.get("cirrus_repo_owner", None)
    req_vals["cirrus_repo_name"] = request.args.get("cirrus_repo_name", None)
    req_vals["cirrus_task_id"] = request.args.get("cirrus_task_id", None)
    req_vals["cirrus_task_name"] = request.args.get("cirrus_task_name", None)
    req_vals["cirrus_build_id"] = request.args.get("cirrus_build_id", None)
    req_vals["cirrus_pr"] = request.args.get("cirrus_pr", None)
    req_vals["cirrus_pr_labels"] = request.args.get("cirrus_pr_labels", None)
    req_vals["github_check_suite_id"] = request.args.get("github_check_suite_id", None)
    req_vals["repo_version"] = request.args.get("repo_version", None)

    return req_vals


def enqueue_job(job_func, req_vals: dict[str, any]):
    """
    Enqueue the given request vals via redis rq for processing.
    """
    redis_host = os.getenv("REDIS_HOST", "localhost")
    queue_name = os.getenv("RQ_QUEUE_NAME", "default")
    queue_default_timeout = int(os.getenv("RQ_DEFAULT_TIMEOUT", "1800"))

    # New connection per request, that's alright for now.
    with redis.Redis(host=redis_host) as redis_conn:
        q = rq.Queue(
            name=queue_name,
            connection=redis_conn,
            default_timeout=queue_default_timeout,
        )

        return q.enqueue(job_func, req_vals)


def create_app(*, config=None):
    """
    Create the zeek-benchmarker app.
    """
    app = Flask(__name__)
    if config:
        app.config.update(config)

    @app.route("/zeek", methods=["POST"])
    def zeek():
        req_vals = parse_request(request)

        # At this point we've validated the request and just
        # enqueue it for the worker to pick up.
        job = enqueue_job(zeek_benchmarker.tasks.zeek_job, req_vals)

        # Store information about this job, too.
        store = storage.Storage(app.config["DATABASE_FILE"])

        # Store the machine information with the job. The assumption
        # here is that the system serving the API is also executing
        # the job. Otherwise this would need to move into tasks.py.
        machine = store.get_or_create_machine(zeek_benchmarker.machine.get_machine())
        store.store_job(
            job_id=job.id,
            kind="zeek",
            machine_id=machine.id,
            req_vals=req_vals,
        )

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
        # At this point we've validated the request and just
        # enqueue it for the worker to pick up.
        req_vals = parse_request(request)
        job = enqueue_job(zeek_benchmarker.tasks.broker_job, req_vals)
        return jsonify(
            {
                "job": {
                    "id": job.id,
                    "enqueued_at": job.enqueued_at,
                }
            }
        )

    return app
