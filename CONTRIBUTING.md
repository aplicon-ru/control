# Contributing

## Before you start

Every change goes through an Issue first — no exceptions, even for typos.
Open one (or find an existing one) before opening a PR, and link it in
the PR description. See `.github/ISSUE_TEMPLATE/`.

## Commits

This repo follows [Conventional Commits](https://www.conventionalcommits.org/).
`feat:`, `fix:`, `docs:`, and `BREAKING CHANGE:` in commit messages drive
the changelog and version bump automatically via release-please — don't
edit `CHANGELOG.md` by hand.

## Sign your commits (DCO)

```
git commit -s
```

This adds a `Signed-off-by` line certifying you wrote the change or have
the right to submit it under the project's license. Required on every
commit.

## Environment

Open this repo in GitHub Codespaces (or VS Code Dev Containers locally) —
the devcontainer has Go, Node, and linters preconfigured. No local setup
needed.

## Before opening a PR

- `golangci-lint run` clean
- `go test ./...` passing
- New code meets patch-coverage threshold: 70% default, 90% for
  `internal/secrets`, `internal/auth`, `internal/license`
- Docs updated if behavior changed
- UI changes pass the accessibility checklist
- See `.github/PULL_REQUEST_TEMPLATE.md` for the full checklist

## License

By contributing, you agree your contribution is licensed under AGPL-3.0
(see `LICENSE`). The DCO sign-off is what makes this official.
