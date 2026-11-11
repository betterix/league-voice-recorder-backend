IMAGE_NAME ?= league-scrim-backend:dev

.PHONY: help build up down restart logs status dev test clean

help:
	@echo "League Voice Recorder Backend Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make build    - Build the dev Docker image ($(IMAGE_NAME))"
	@echo "  make up       - Launch the container using pre-built image with docker compose"
	@echo "  make dev      - Build the dev image and launch with docker compose"
	@echo "  make down     - Stop and remove the container"
	@echo "  make restart  - Restart the container"
	@echo "  make logs     - View live container logs"
	@echo "  make status   - Show container status and health"
	@echo "  make test     - Run pytest test suite"

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
	uv run pytest -v
