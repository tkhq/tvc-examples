#!/bin/sh
set -eu
pyinstaller --clean --noconfirm --onefile --name broker --paths . \
  --collect-data mcp --collect-data mcp_types \
  --copy-metadata mcp --copy-metadata mcp-types \
  --hidden-import uvicorn.logging --hidden-import uvicorn.loops.asyncio \
  --hidden-import uvicorn.protocols.http.h11_impl \
  --hidden-import uvicorn.lifespan.on packaging/entry.py
staticx dist/broker /app/pivot
if readelf -l /app/pivot | rg INTERP; then
  echo "Pivot still requires an external ELF loader" >&2
  exit 1
fi
