#!/bin/bash

docker build -f Dockerfile.docs . -t docs-temp
docker run --rm -v "$PWD/docs":/src/_site docs-temp:latest

