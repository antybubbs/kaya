.PHONY: build run stop logs shell release

build:
	docker build -t keyvault:local .

run:
	docker compose up -d --build

stop:
	docker compose down

logs:
	docker compose logs -f keyvault

shell:
	docker compose exec keyvault /bin/sh

release:
	@test -n "$(VERSION)" || (echo "Usage: make release VERSION=v1.0.0" && exit 1)
	git tag $(VERSION)
	git push origin $(VERSION)
