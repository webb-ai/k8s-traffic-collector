#!/usr/bin/env bash

aws ecr-public get-login-password --region us-east-1 | docker login --username AWS --password-stdin public.ecr.aws/p5v6t9h8
DOCKER_REPO="public.ecr.aws/p5v6t9h8/k8s-traffic-collector"
DOCKER_TAG=$(git describe --dirty --tags)
docker build . -t ${DOCKER_REPO}:${DOCKER_TAG}-amd64 --build-arg BUILDARCH=amd64 --build-arg TARGETARCH=amd64 --push
docker build . -t ${DOCKER_REPO}:${DOCKER_TAG}-arm64v8 --build-arg BUILDARCH=amd64 --build-arg TARGETARCH=arm64v8 --push

sleep 10
docker manifest create ${DOCKER_REPO}:${DOCKER_TAG} ${DOCKER_REPO}:${DOCKER_TAG}-amd64 ${DOCKER_REPO}:${DOCKER_TAG}-arm64v8
docker manifest push ${DOCKER_REPO}:${DOCKER_TAG}

