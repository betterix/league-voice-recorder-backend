IMAGE_NAME ?= league-scrim-backend:dev

.PHONY: help build up down restart logs status dev test clean bump

help:
	@echo "League Voice Recorder Backend Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make build              - Build the dev Docker image ($(IMAGE_NAME))"
	@echo "  make up                 - Launch the container using pre-built image with docker compose"
	@echo "  make dev                - Build the dev image and launch with docker compose"
	@echo "  make down               - Stop and remove the container"
	@echo "  make restart            - Restart the container"
	@echo "  make logs               - View live container logs"
	@echo "  make status             - Show container status and health"
	@echo "  make test               - Run Cargo test suite"
	@echo "  make bump VERSION=x.y.z - Bump version everywhere from one place"

build:
	docker build -t $(IMAGE_NAME) .

up:
	docker compose up -d

dev: build up

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f league-scrim-backend

status:
	docker compose ps

test:
	cargo test

bump:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make bump VERSION=1.3.5"; exit 1; fi
	@OLD=$$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2); \
	echo "Bumping version $$OLD -> $(VERSION)"; \
	sed -i '0,/^version = ".*"/s//version = "$(VERSION)"/' Cargo.toml; \
	sed -i 's/ARG APP_VERSION=.*/ARG APP_VERSION=$(VERSION)/' Dockerfile; \
	sed -i 's/"version": "[^"]*"/"version": "$(VERSION)"/' docs/API_REFERENCE.md; \
	sed -i 's/Docs Hub v[0-9.]*/Docs Hub v$(VERSION)/' web/index.html; \
	sed -i 's/&quot;version&quot;: &quot;[^&]*&quot;/\&quot;version\&quot;: \&quot;$(VERSION)\&quot;/' web/index.html; \
	cargo check --quiet; \
	echo "Updated all files and Cargo.lock to $(VERSION)"
