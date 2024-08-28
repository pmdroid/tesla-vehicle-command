#!/usr/bin/env bash
cd protobuf/
nanopb_generator ./*.proto
cd ..
cp protobuf/*.c src/
cp protobuf/*.h include/
sed -i '/#include "google\/protobuf\/timestamp.pb.h"/d' include/car_server.pb.h
rm protobuf/*.c
rm protobuf/*.h