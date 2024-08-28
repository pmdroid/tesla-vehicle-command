#!/usr/bin/env bash

git apply --ignore-space-change --ignore-whitespace patches/mbedtls2.patch
echo "updated code to run with mbedtls2"

mkdir TeslaBLE
cp src/* TeslaBLE/
cp include/* TeslaBLE/
zip -r library.zip TeslaBLE
rm -rf TeslaBLE

echo "created library.zip"