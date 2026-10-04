# Notifications

ReqSentry can route incidents and recurring operational alerts to named Slack, Microsoft Teams, and Amazon SNS destinations. Remote delivery is optional and independent of SQLite/JSONL output. The `output` section of the [complete configuration example](../configs/example.yaml) includes commented Slack, Teams, and SNS settings.

Each `output.destinations` entry has a unique `name`, `type`, and `enabled` flag. Incident routing supports `minimum_score` (0–100), `decisions`, and `sites`. Omit a filter to include all values; an empty string in `sites` explicitly includes server-wide incidents. Operational alerts use a separate `operational: true` subscription and are sent after at least three consecutive failures. Site/score filters apply to incident alerts, not operational alerts.

Existing `output.slack` settings still work with their configured score floor, cooldown, and operational subscriptions. The CLI adapts them into the shared delivery worker. Use either legacy Slack configuration or named Slack destinations; enabling both is rejected to prevent duplicate Slack alerts.

## Delivery behavior

Every destination has an independent bounded queue (default 128, maximum 1,024) and worker, per-client/site/signal cooldown (default ten minutes), and bounded deduplication state. Workers send at most four messages per second before retries. A failed destination cannot block another or the log watchers. Default retry limits are three attempts and one minute from enqueue time; `max_attempts`, `max_age`, and `queue_size` are configurable. Retries use exponential backoff with jitter and honor HTTP retry hints within the remaining age budget. Webhook redirects are rejected; permanent HTTP failures do not retry. Queue overflow, expired messages, failed deliveries, suppression, retries, and last provider acceptance appear in `status.notifications`.

Queues and cooldowns are in memory, so restarts may lose pending messages or repeat alerts. An ambiguous network timeout can also cause duplicate delivery. Provider acceptance is not proof of Teams posting, subscriber receipt, or human acknowledgment. Operational remote messages summarize the failing source and recurrence count; inspect local diagnostics for details. Notification failures do not create recursive remote failure alerts.

Configuration checks, preview, and replay send no messages. To explicitly send a synthetic test to an enabled destination (legacy `output.slack` uses `legacy-slack`):

```sh
reqsentry -config /etc/reqsentry/config.yaml notifications test teams-operations
```

The response reports provider acceptance; check the destination separately. All incident messages state monitor mode and no action taken. Card/text fields are bounded and escaped; messages do not include stack traces. SNS JSON includes redacted correlation samples, but excludes local stack traces.

## Slack preview and setup

The [config reference](../configs/example.yaml) includes legacy `output.slack` and named Slack destinations. Choose one style. Configure an incoming-webhook secret via `webhook_env` or `webhook_credential`; never write the URL in YAML. The accepted endpoints are HTTPS incoming-webhook URLs under `hooks.slack.com` or `hooks.slack-gov.com` with a `/services/` path.

```sh
# Works without Slack credentials; sends nothing:
reqsentry -config /etc/reqsentry/config.yaml notifications preview
# Explicitly sends a synthetic test after setup:
reqsentry -config /etc/reqsentry/config.yaml notifications test legacy-slack
```

The offline preview uses the actual incident formatter and fictional values. Outgoing incident text includes server/site/IP, analysis window, request count, peak rate, up to four evidence codes, score/decision, optional CPU/ASN/enrichment, and the monitor-only notice. Full evidence remains in the CLI report and stored incident.

Omit the test name when exactly one destination is enabled; multiple destinations require an explicit name. The test command supports both legacy Slack and named destinations. Shell commands need the configured secret in the calling environment or `CREDENTIALS_DIRECTORY`; systemd does not export its credentials to your shell. Check the destination to confirm receipt. See [CLI credentials and operations](cli.md).

## Microsoft Teams

Create a Teams Workflows incoming-webhook workflow that posts the received Adaptive Card attachment to the desired chat/channel. Use a trigger configured to accept requests from anyone with its secret webhook URL; tenant/user OAuth triggers are not supported by this adapter. Keep the URL in the environment named by `webhook_env`, or use `webhook_credential` for a systemd credential. Only HTTPS Workflows endpoints under `*.logic.azure.com` or `*.environment.api.powerplatform.com` are accepted; legacy connector URLs are not supported. URLs and provider response bodies are never printed in delivery diagnostics.

The outgoing payload is `type: message` with `application/vnd.microsoft.card.adaptive` attachments and an Adaptive Card 1.2 body. Use a workflow that accepts this payload; a template expecting only a `text` field needs adaptation. Set an optional public HTTPS `dashboard_url` for a dashboard link; existing dashboard authentication still applies. Payloads have a conservative 24 KiB limit and text truncation labels.

Assign workflow co-owners so notifications do not depend on one employee's account. Follow [Microsoft's Workflows guidance](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook) for tenant/channel restrictions and ownership. HTTP success acknowledges the webhook; the workflow can still fail while posting. Check the workflow run history and perform a controlled smoke test before relying on a tenant configuration.

## Amazon SNS

Set `type: sns`, a standard topic `topic_arn`, and its matching `region`. FIFO topics are rejected until grouping/deduplication semantics are supported. Credentials use the AWS SDK default chain, including environment credentials, shared profiles, and supported instance/task roles. `aws_profile` selects a shared profile. Keep static keys out of YAML.

Grant `sns:Publish` only on the selected topic. Cross-account publishing also requires the topic's resource policy; encrypted topics may require permissions on the KMS key. Create/manage topics and subscriptions separately. This integration does not send SMS directly or create AWS infrastructure.

The UTF-8 message string contains a version-1 JSON envelope with `event_id`, `event_kind`, `server`, optional `site`, `timestamp`, `monitor_only`, and incident or operational content. The incident contains its analysis window. Error messages and stacks are omitted from SNS exports; correlation counts and association metadata remain. It is ordinary JSON in `Message`, not SNS protocol-specific `MessageStructure=json`. Attributes include `event_kind`, `site`, and `decision` for incidents; server-wide incidents use attribute `site=all-sites` while the JSON incident keeps its empty `site_id`. Payloads reserve attribute space within a conservative 256 KiB budget; oversized optional signal evidence is removed with `truncated: true`, and still-oversized messages fail visibly. SNS subscribers can deduplicate stable event IDs across retries. SDK retry attempts are disabled so the shared worker owns the attempt budget. Credential and client-side API failures terminate the current delivery without retries; throttling, server failures, and eligible transport failures use the shared bounded retry policy.

[AWS's Publish API](https://docs.aws.amazon.com/sns/latest/api/API_Publish.html) describes regional/topic publishing and message attributes. The status acknowledgment is the returned SNS message ID, not downstream delivery confirmation. After sending a test, check the intended subscriber to confirm delivery.
