# Repo Policy

- `ecosystem` is the private canonical remote. Push normal development branches, full source commits, and private-only work there.
- `origin` is the public release remote. Do not push normal source branches or `main` there unless the user explicitly asks for a public branch update.
- Before any public `origin` release push, confirm whether the user wants `tag-only` or a branch update. Public tags still expose the tagged source snapshot.
- Default push behavior should stay on `ecosystem`. Public pushes to `origin` should be explicit and deliberate.
- Keep local scratch outputs uncommitted. Do not add `handlers.test`, `dist/v*/`, or `logs/deploy-api-*.log`.
