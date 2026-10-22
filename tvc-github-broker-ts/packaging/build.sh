#!/bin/sh
set -eu
npm run check
npm run bundle
node --experimental-sea-config packaging/sea.json
cp /usr/local/bin/node dist/broker-sea
npx --no-install postject dist/broker-sea NODE_SEA_BLOB dist/broker.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
/opt/packaging/bin/staticx dist/broker-sea /app/pivot
if readelf -l /app/pivot | rg INTERP; then
  echo "Pivot still requires an external ELF loader" >&2
  exit 1
fi
