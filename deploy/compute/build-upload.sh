#!/usr/bin/env bash

JAR_TAG=${1:-dev}

sbt assembly && \
version="$(cat  version.sbt  | cut -d '-' -f 1 | cut -d '"' -f 2)"
gsutil cp target/scala-2.12/constellation-assembly-$versionjar gs://constellation-dag/release/dag-$JAR_TAG.jar && \
gsutil acl ch -u AllUsers:R gs://constellation-dag/release/dag-$JAR_TAG.jar
