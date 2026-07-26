.PHONY: build run stop logs shell release

build:
	docker build -t kaya:local .

run:
	docker compose up -d --build

stop:
	docker compose down

logs:
	docker compose logs -f kaya

shell:
	docker compose exec kaya /bin/sh

release:
	@test -n "$(VERSION)" || (echo "Usage: make release VERSION=v1.0.0" && exit 1)
	@printf '%s\n' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$' || (echo "VERSION must match vMAJOR.MINOR.PATCH" && exit 1)
	@command -v gh >/dev/null 2>&1 || (echo "GitHub CLI (gh) is required to publish a release" && exit 1)
	git tag $(VERSION)
	git push origin $(VERSION)
	gh release create $(VERSION) --verify-tag --generate-notes --title $(VERSION)
