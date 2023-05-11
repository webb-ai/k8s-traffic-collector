#!/usr/bin/env bash

aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws/p5v6t9h8
export DOCKER_REPO="public.ecr.aws/p5v6t9h8/ebpf-worker"
export DOCKER_TAG="latest"
docker build . -t ${DOCKER_REPO}:${DOCKER_TAG} --build-arg BUILDARCH=amd64 --build-arg TARGETARCH=amd64
docker push ${DOCKER_REPO}:${DOCKER_TAG}

kubectl rollout restart ds kubeshark-worker-daemon-set -n ks

