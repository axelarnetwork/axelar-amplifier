SUFFIX := $(shell echo $$PLATFORM | sed 's/\//-/' | sed 's/\///')

# DOCKER_OUTPUT is the buildx --output value and is supplied by the caller:
#   type=image,push=true                pushes the image to the registry
#   type=docker,dest=<dir>/<name>.tar   writes a docker load-able tarball
# The caller is responsible for creating <dir> beforehand.
.PHONY: build-docker-image
build-docker-image:
	@DOCKER_BUILDKIT=1 docker buildx build \
		--platform ${PLATFORM} \
		--output "${DOCKER_OUTPUT}" \
		--build-arg ARCH="${ARCH}" \
		-f ampd/Dockerfile \
		-t axelarnet/axelar-ampd-${SUFFIX}:${SEMVER} --provenance=false .

.PHONY: build-handler-docker-image
build-handler-docker-image:
	@DOCKER_BUILDKIT=1 docker buildx build \
		--platform ${PLATFORM} \
		--output "${DOCKER_OUTPUT}" \
		--build-arg HANDLER=${HANDLER} \
		-f ampd-handlers/Dockerfile \
		-t axelarnet/axelar-ampd-${HANDLER}-handler-${SUFFIX}:${SEMVER} --provenance=false .
