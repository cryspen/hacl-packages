#!/usr/bin/env bash

set -e
set -o pipefail

if [[ $1 == "-h" || $1 == "--help" || $1 == "" ]]; then
  echo "Usage: $0 [EVEREST-REVISION]"
  echo
  echo "Creates a container with a successful build of HACL* based on the provided Everest revision"
  exit 1
fi

# Essentially this, with a few customizations:
# https://raw.githubusercontent.com/project-everest/everest-ci/master/server-infra/linux/.docker/Dockerfile
docker build -t everest_base_image:1 everest --progress=plain
docker build . --progress=plain --build-arg everest_revision=$1
