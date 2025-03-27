"""
Testing client for the benchmarker API.

Usage:

    $ python3 client.py mybranch \
        --build-url http://localhost:8000/builds/5721034205167616/build.tgz \
        --build-hash d3de665720ed5e752275269d3fca62a0696700a6e61306fc392f1514b2083da7


"""

import argparse
import hmac
import logging
import time

import requests

logger = logging.getLogger(__name__)


class Client:
    def __init__(self, url, hmac_key):
        self.url = url.strip("/")
        self._session = requests.Session()
        self._hmac_key = hmac_key

    def _submit_build(
        self,
        *,
        path,
        branch,
        build_url,
        build_hash,
        commit=None,
        cirrus_task_name=None,
        hmac_ts=None,
    ):
        """ """
        hmac_ts = int(time.time()) if hmac_ts is None else hmac_ts
        url = "/".join([self.url, path.lstrip("/")])
        params = {
            "branch": branch,
            "build": build_url,
        }

        if build_hash:
            params["build_hash"] = build_hash

        if commit:
            params["commit"] = commit

        if cirrus_task_name:
            params["cirrus_task_name"] = cirrus_task_name

        hmac_msg = f"{path:s}-{hmac_ts:d}-{build_hash:s}\n".encode()
        hmac_digest = hmac.digest(self._hmac_key, hmac_msg, "sha256").hex()
        headers = {
            "Zeek-HMAC": hmac_digest,
            "Zeek-HMAC-Timestamp": str(hmac_ts),
        }

        r = self._session.post(url, params=params, headers=headers)
        r.raise_for_status()
        return r

    def submit_zeek(
        self,
        *,
        branch,
        build_url,
        build_hash,
        commit=None,
        cirrus_task_name=None,
        hmac_ts=None,
    ):
        """
        Submit a benchmark request to /zeek
        """
        return self._submit_build(
            path="/zeek",
            branch=branch,
            build_url=build_url,
            build_hash=build_hash,
            commit=commit,
            cirrus_task_name=cirrus_task_name,
            hmac_ts=hmac_ts,
        )

    def submit_broker(
        self,
        *,
        branch,
        build_url,
        build_hash,
        commit=None,
        cirrus_task_name=None,
        hmac_ts=None,
    ):
        """
        Submit a benchmark request to /broker
        """
        return self._submit_build(
            path="/broker",
            branch=branch,
            build_url=build_url,
            build_hash=build_hash,
            commit=commit,
            cirrus_task_name=cirrus_task_name,
            hmac_ts=hmac_ts,
        )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--api-url", default="http://localhost:8080")
    p.add_argument("--hmac-key", type=lambda s: s.encode(), default="unset")
    p.add_argument("--build-url", type=str, default="")
    p.add_argument("--build-hash", type=str, default=None, required=True)
    p.add_argument("--cirrus-task-name", type=str, default=None, required=True)
    p.add_argument("--commit", type=str, default=None)
    p.add_argument("what", choices=["broker", "zeek"])
    p.add_argument("branch")
    args = p.parse_args()

    logging.basicConfig()

    c = Client(args.api_url, args.hmac_key)
    if args.what == "zeek":
        submit_func = c.submit_zeek
    elif args.what == "broker":
        submit_func = c.submit_broker
    else:
        raise NotImplementedError(args.what)

    try:
        r = submit_func(
            branch=args.branch,
            build_url=args.build_url,
            build_hash=args.build_hash,
            commit=args.commit,
            cirrus_task_name=args.cirrus_task_name,
        )
        r.raise_for_status()
        print(r.json())
    except requests.HTTPError as e:
        logger.error("%s: %s", e.response.status_code, e.response.content)
        return 1


if __name__ == "__main__":
    main()
