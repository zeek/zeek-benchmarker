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

    def _submit_build(self, path, branch, build_url, build_hash, hmac_ts=None):
        """ """
        hmac_ts = int(time.time()) if hmac_ts is None else hmac_ts
        url = "/".join([self.url, path.lstrip("/")])
        params = {
            "branch": branch,
            "build": build_url,
        }

        if build_hash:
            params["build_hash"] = build_hash

        hmac_msg = f"/zeek-{hmac_ts:d}-{build_hash:s}\n".encode()
        hmac_digest = hmac.digest(self._hmac_key, hmac_msg, "sha256").hex()
        headers = {
            "Zeek-HMAC": hmac_digest,
            "Zeek-HMAC-Timestamp": str(hmac_ts),
        }

        r = self._session.post(url, params=params, headers=headers)
        r.raise_for_status()
        return r

    def submit_zeek(self, *, branch, build_url, build_hash, hmac_ts=None):
        """
        Submit a benchmark request to /zeek
        """
        return self._submit_build(
            "/zeek", branch, build_url, build_hash, hmac_ts=hmac_ts
        )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--api-url", default="http://localhost:8080")
    p.add_argument("--hmac-key", type=lambda s: s.encode(), default="unset")
    p.add_argument("--build-url", type=str, default="")
    p.add_argument("--build-hash", type=str, default=None, required=True)
    p.add_argument("branch")
    args = p.parse_args()

    logging.basicConfig()

    c = Client(args.api_url, args.hmac_key)

    try:
        r = c.submit_zeek(
            branch=args.branch,
            build_url=args.build_url,
            build_hash=args.build_hash,
        )
        r.raise_for_status()
        print(r.json())
    except requests.HTTPError as e:
        logger.error("%s: %s", e.response.status_code, e.response.content)
        return 1


if __name__ == "__main__":
    main()
