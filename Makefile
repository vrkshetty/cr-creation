IMAGE ?= cr-drafter
ENV_FILE ?= .env
OUTPUT ?= $(CURDIR)/output

.DEFAULT_GOAL := run
.PHONY: build run mock check-env

build:
	docker build -t "$(IMAGE)" .

# The env file is passed at run time, so secrets are never stored in the image
run: check-env build
	mkdir -p "$(OUTPUT)"
	docker run --rm --env-file "$(ENV_FILE)" -v "$(OUTPUT):/app/output" "$(IMAGE)"

# Uses the sample data, so it needs no env file or real servers
mock: build
	mkdir -p "$(OUTPUT)"
	docker run --rm -e MOCK_MODE=true -v "$(OUTPUT):/app/output" "$(IMAGE)"

check-env:
	@test -f "$(ENV_FILE)" || { echo "$(ENV_FILE) not found: run 'cp .env.example $(ENV_FILE)' and fill it in" >&2; exit 1; }
