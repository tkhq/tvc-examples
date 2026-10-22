"""Packaging-only entrypoint. Normal Python/OCI runs use server.py directly."""

import sys

import httpx

from server import main

if "--self-test" in sys.argv:
    # Exercises the bundled interpreter, native extensions, DNS, and CA bundle.
    response = httpx.get("https://api.github.com/", timeout=10)
    response.raise_for_status()
    print("Bundled Python runtime, DNS, and HTTPS: OK")
else:
    main()
