#!/usr/bin/env bash

echo "mbedtls 2 vs 3 is selected in source via MBEDTLS_VERSION_MAJOR; no crypto patch required"
if [ -f patches/mbedtls2.patch ]; then
  git apply --ignore-space-change --ignore-whitespace patches/mbedtls2.patch || true
fi

mkdir TeslaBLE
cp src/* TeslaBLE/
cp include/* TeslaBLE/
zip -r library.zip TeslaBLE
rm -rf TeslaBLE

echo "created library.zip"