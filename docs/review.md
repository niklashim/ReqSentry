# Release checks

Use this checklist when preparing a ReqSentry release. [Testing and validation](validation.md) describes the commands and deployment checks.

## Automated checks

- Run the full Go race suite, static checks, and configuration validation.
- Run constrained-scheduler storage/watcher regressions and dashboard tests.
- Audit dependencies and scan source, the actual release binary, and the runtime image.
- Build the supported Linux target and check service startup, shutdown, rotation, and restart behavior.

## Documentation and examples

- Check that CLI examples match the release's commands, flags, and output.
- Validate the complete commented config and Docker example config.
- Keep setup and usage guides focused on supported behavior.
- Use synthetic data for examples and media, and label simulated enrichment/health context.

## Source and package contents

Inspect the source tree, container build context, and Git history for private configuration, credentials, production logs, runtime databases, and personal data. Ignore rules apply to untracked files; they do not remove previously committed content. Keep licensed MaxMind downloads outside the release package. Preserve the MIT license and third-party notices.

## Deployment checks

Review representative production traffic and measure sustained resource use on the intended Linux host. Verify live notification receipt for each configured Slack, Teams, or SNS destination. Check service permissions, proxy trust, retention, recovery, and optional dashboard access rules. Provider contract tests and synthetic workloads complement these checks; they do not replace account- and host-specific validation.
