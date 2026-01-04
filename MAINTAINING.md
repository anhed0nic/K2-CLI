# Maintaining Khao2

Guide for project maintainers.

## Release Process

### Version Bumping

1. Update version in `setup.py`
2. Update `CHANGELOG.md` with release notes
3. Commit: `git commit -m "chore: bump version to X.Y.Z"`
4. Tag: `git tag vX.Y.Z`
5. Push: `git push origin main --tags`

### Publishing to PyPI

The GitHub Actions workflow handles publishing automatically when a tag is pushed.

Manual release (if needed):
```bash
python -m build
twine upload dist/*
```

## Issue Triage

### Labels
- `bug` - Something isn't working
- `enhancement` - New feature request
- `documentation` - Docs improvements
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `wontfix` - Won't be addressed
- `duplicate` - Duplicate issue

### Priority
- P0: Critical - security issues, data loss
- P1: High - major functionality broken
- P2: Medium - important but not urgent
- P3: Low - nice to have

## Pull Request Review

### Checklist
- [ ] Code follows project style
- [ ] Tests pass
- [ ] Documentation updated if needed
- [ ] Changelog updated for user-facing changes
- [ ] No security concerns
- [ ] Backwards compatible (or breaking change documented)

### Merging
- Squash and merge for most PRs
- Rebase and merge for clean commit histories
- Delete branch after merge

## Security

- Monitor dependencies for vulnerabilities
- Review security reports within 48 hours
- Coordinate disclosure for critical issues
- Keep `SECURITY.md` up to date

## Communication

- Respond to issues within a week
- Be welcoming to new contributors
- Provide constructive feedback on PRs
- Update README for significant changes

## Dependencies

Review and update dependencies quarterly:
```bash
pip list --outdated
```

## Contacts

- Primary maintainer: Odin Glynn-Martin (odin@odinglynn.com)
- Website: https:/www.khao2.com
