#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root/protobuf"
PYTHON="${PYTHON:-python3}"
"$PYTHON" "$root/build/_deps/nanopb-src/generator/nanopb_generator.py" \
  --proto-path=. \
  car_server.proto common.proto errors.proto keys.proto managed_charging.proto \
  signatures.proto universal_message.proto vcsec.proto vehicle.proto
cp ./*.c "$root/src/"
cp ./*.h "$root/include/"
for header in "$root/include"/*.pb.h; do
  sed -i.bak '/#include "google\/protobuf\/timestamp.pb.h"/d' "$header"
  rm -f "$header.bak"
done
rm -f ./*.c ./*.h
rm -rf google/protobuf/*.pb.c google/protobuf/*.pb.h 2>/dev/null || true
