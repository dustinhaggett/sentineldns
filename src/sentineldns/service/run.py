from __future__ import annotations

import argparse

import uvicorn

from sentineldns.config import DEFAULT_SERVICE_HOST, DEFAULT_SERVICE_PORT


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SentinelDNS local inference service")
    parser.add_argument("--host", default=DEFAULT_SERVICE_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_SERVICE_PORT)
    args = parser.parse_args()
    uvicorn.run("sentineldns.service.api:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
