PUSH_DOCKER_IMAGE := true
SUFFIX := $(shell echo $$PLATFORM | sed 's/\//-/' | sed 's/\///')

.PHONY: build-push-docker-image
build-push-docker-images:
	@DOCKER_BUILDKIT=1 docker buildx build \
		--platform ${PLATFORM} \
		--output "type=image,push=${PUSH_DOCKER_IMAGE}" \
		--build-arg ARCH="${ARCH}" \
		-f ampd/Dockerfile \
		-t axelarnet/axelar-ampd-${SUFFIX}:${SEMVER} --provenance=false .
