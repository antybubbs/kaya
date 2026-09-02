.PHONY: build run stop logs shell release release-dev release-rc

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
	git tag "$(VERSION)"
	git push origin "$(VERSION)"
	gh release create "$(VERSION)" --verify-tag --generate-notes --title "$(VERSION)"

release-dev:
	@test -n "$(VERSION)" || (echo "Usage: make release-dev VERSION=v1.0.0-dev.1" && exit 1)
	@printf '%s\n' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-dev\.[0-9]+$$' || (echo "VERSION must match vMAJOR.MINOR.PATCH-dev.N" && exit 1)
	@command -v gh >/dev/null 2>&1 || (echo "GitHub CLI (gh) is required to publish a release" && exit 1)
	git tag "$(VERSION)"
	git push origin "$(VERSION)"
	gh release create "$(VERSION)" --verify-tag --prerelease --generate-notes --title "$(VERSION)"

release-rc:
	@test -n "$(VERSION)" || (echo "Usage: make release-rc VERSION=v1.0.0-rc.1" && exit 1)
	@printf '%s\n' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$$' || (echo "VERSION must match vMAJOR.MINOR.PATCH-rc.N" && exit 1)
	@command -v gh >/dev/null 2>&1 || (echo "GitHub CLI (gh) is required to publish a release" && exit 1)
	git tag "$(VERSION)"
	git push origin "$(VERSION)"
	gh release create "$(VERSION)" --verify-tag --prerelease --generate-notes --title "$(VERSION)"
