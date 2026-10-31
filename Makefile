.PHONY: verify verify-fast verify-lint lint-api lint-web verify-version verify-api verify-web verify-bridge verify-compose verify-smoke verify-zfs-image

# Host toolchains. A repo-local .venv wins if present; otherwise PATH.
VENV ?= $(CURDIR)/.venv
PYTHON ?= $(if $(wildcard $(VENV)/bin/python),$(VENV)/bin/python,python3)
RUFF ?= $(if $(wildcard $(VENV)/bin/ruff),$(VENV)/bin/ruff,ruff)
NPM ?= npm
GO ?= go

# Verification isolation (Mf-ly4o). Everything mutable a verification run
# creates - test DB, test storage, image tags, compose project name, host
# ports - is namespaced by MV_RUN_ID so two runs can share one host and one
# Docker daemon. Default: this make process's pid plus the worktree directory,
# which keeps concurrent runs apart with no setup. Set MV_RUN_ID to join a lane
# (see curiarium/docs/DEVELOPMENT.md).
ifeq ($(strip $(MV_RUN_ID)),)
MV_RUN_ID := $(shell echo "$$PPID-$$(basename "$(CURDIR)")")
endif
# Image tags and compose project names allow only [a-z0-9_.-] (project names
# also must start with an alphanumeric), so normalise whatever MV_RUN_ID holds.
# Dots become dashes too: the smoke script and the API tests allow only
# [a-z0-9_-], and one normalisation for all three keeps a lane's tag, project
# name and test path spelled the same way.
RUN_ID := $(shell printf '%s' '$(MV_RUN_ID)' | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9_-]/-/g')
export MV_RUN_ID

API_TEST_IMAGE ?= curiarium-api-gate0-test:$(RUN_ID)
WEB_TEST_IMAGE ?= curiarium-web-gate0-test:$(RUN_ID)
API_LINT_IMAGE ?= curiarium-api-lint:$(RUN_ID)
WEB_LINT_IMAGE ?= curiarium-web-lint:$(RUN_ID)
API_PLAIN_IMAGE ?= curiarium-api-plain:$(RUN_ID)
API_ZFS_IMAGE ?= curiarium-api-zfs:$(RUN_ID)

# Full gate. Run once per wave (or per ticket when it touches migrations,
# Dockerfiles, nginx.conf, compose manifests or dependency locks).
verify: verify-lint verify-api verify-web verify-bridge verify-compose verify-smoke verify-zfs-image

# Fast gate (~20s, no image builds, no container smoke). Run per ticket while
# iterating; the wave still ends on `make verify`.
verify-fast: verify-version verify-fast-api verify-fast-web verify-fast-bridge

verify-fast-api:
	cd curiarium/api && $(RUFF) check . && $(PYTHON) -m pytest -q

verify-fast-web:
	cd curiarium/web && $(NPM) run lint && $(NPM) run typecheck && $(NPM) run test:run

verify-fast-bridge:
	cd curiarium/slicer-bridge && $(GO) test ./...

verify-lint: lint-api lint-web

lint-api:
	docker build --target lint -t $(API_LINT_IMAGE) curiarium/api
	docker image rm $(API_LINT_IMAGE) >/dev/null 2>&1 || true

lint-web:
	docker build --target lint -t $(WEB_LINT_IMAGE) curiarium/web
	docker image rm $(WEB_LINT_IMAGE) >/dev/null 2>&1 || true

# Version drift guard (Mf-cvoo). `python3` on CI runners, repo .venv locally.
verify-version:
	$(PYTHON) curiarium/scripts/check_version.py

verify-api: verify-version
	docker build --target test -t $(API_TEST_IMAGE) curiarium/api
	status=0; docker run --rm $(API_TEST_IMAGE) || status=$$?; \
		docker image rm $(API_TEST_IMAGE) >/dev/null 2>&1 || true; exit $$status

verify-web: verify-version
	status=0; docker build --target test -t $(WEB_TEST_IMAGE) curiarium/web || status=$$?; \
		docker image rm $(WEB_TEST_IMAGE) >/dev/null 2>&1 || true; exit $$status

verify-bridge:
	docker run --rm \
		-v "$(CURDIR)/curiarium/slicer-bridge:/src" \
		-w /src golang:1.21.13 \
		sh -c 'go test ./... && go build -o /tmp/curiarium-bridge ./cmd/slicer-bridge'

verify-compose:
	cd curiarium && docker compose -f docker-compose.yml config -q
	cd curiarium && docker compose -f docker-compose.deploy.yml config -q
	cd curiarium && docker compose -f docker-deploy.yml config -q
	cd curiarium && docker compose -f docker-compose.yml -f docker-compose.smoke.yml config -q

verify-smoke:
	./curiarium/scripts/container-smoke.sh

# The published API image is slim on purpose, and the -zfs variant (Mf-qirh) is
# the same Dockerfile built with INSTALL_ZFS=1. Both halves are asserted: a `zfs`
# in the plain image would ship to every deployment, and a missing one in the
# variant is the bug the variant exists to prevent. CI has no /dev/zfs, so the
# check can only prove the userspace: `zfs --version` prints the package version
# and then exits 1 with "zfs_version_kernel() failed", which is why the version
# line is matched rather than the exit status.
verify-zfs-image:
	status=0; \
	docker build -t $(API_PLAIN_IMAGE) curiarium/api || status=$$?; \
	if [ $$status -eq 0 ]; then \
		docker build --build-arg INSTALL_ZFS=1 -t $(API_ZFS_IMAGE) curiarium/api || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		docker run --rm --entrypoint /bin/sh $(API_PLAIN_IMAGE) -c 'if command -v zfs; then echo "the plain API image contains zfs; only the -zfs variant may (Mf-qirh)" >&2; exit 1; fi' || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		docker run --rm --entrypoint /bin/sh $(API_ZFS_IMAGE) -c 'command -v zfs || { echo "the -zfs API image has no zfs binary" >&2; exit 1; }; zfs --version 2>&1 | grep -E "^zfs-[0-9]" || { echo "zfs --version printed no userspace version" >&2; exit 1; }' || status=$$?; \
	fi; \
	docker image rm $(API_PLAIN_IMAGE) $(API_ZFS_IMAGE) >/dev/null 2>&1 || true; \
	exit $$status
