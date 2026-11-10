# Event-driven wake-up for the existing local CI fleet

This is a wake-up adapter, not a new CI executor. The existing `local-ci-fleet.service` retains its lock, durable SQLite queue, allowlist, source verification, isolated execution and exact-commit reporting. Its five-minute timer remains enabled for missed events and recovery.

The Python receiver listens on `127.0.0.1:18763/github` only. A trusted HTTPS relay must deliver GitHub webhooks to that loopback endpoint. Configure the GitHub webhook with `application/json`, `push` and `pull_request` events, and the same randomly generated secret stored as a root-independent owner-readable file at `~/.local/share/local-ci/secrets/webhook-hmac` (mode `0600`, directory `0700`). Do not commit or log the secret. Require HTTPS and an authenticated tunnel; do not expose the loopback receiver directly to the internet.

For installation on `web`, copy `scripts/ci-webhook-server.py` to `~/.local/share/local-ci/fleet_webhook_server.py`, `scripts/ci-webhook-wakeup.py` to `~/.local/share/local-ci/fleet_webhook_wakeup.py`, and `scripts/local-ci-webhook.service` to `~/.config/systemd/user/local-ci-webhook.service`. After the secret and relay are provisioned, run `systemctl --user daemon-reload` and `systemctl --user enable --now local-ci-webhook.service`. Do not enable the service before the secret exists.

Every event is authenticated with GitHub's HMAC-SHA256 signature, limited by size, event type and repository. Accepted events only request `systemctl --user start --no-block local-ci-fleet.service`. They cannot choose a job, command, branch, checkout or credentials. The controller queries GitHub independently. An invalid signature or repository is refused. The listener returns 503 if it cannot request a wake-up; polling still provides eventual recovery.

**Acceptance evidence (6 November 2026):** [PR #96](https://github.com/AyobamiH/clawsweeper/pull/96) proved genuine GitHub push/PR delivery, the authenticated relay, existing local-fleet execution and an independently read-back exact-SHA `local-ci/linux-node24: success` status. The matching local receipt is `local-fleet-0420e32a049b` at `a609a6de2dd657feb77a360be34e8abaf5dd308c`, with five successful validation stages and a matching log digest. PR #96 was closed without merging.

**New installations must prove their own acceptance.** Require a genuine GitHub event through the configured relay, exact-SHA status and local receipt. Verify no duplicate work and that failed delivery is eventually recovered by the five-minute timer. Keep deployment credentials and untrusted PR execution isolated.

## Replayed GitHub delivery handling

The receiver now requires `FLEET_WEBHOOK_LEDGER_DIR`, an owner-only `0700` directory precreated at `~/.local/share/local-ci/webhook-deliveries` before installing or restarting the service. Add the exact directory to the systemd unit's `ReadWritePaths`; do not remove `ProtectSystem=strict` or `ProtectHome=read-only`. Install `scripts/ci-webhook-deliveries.py` beside the existing installed `fleet_webhook_server.py` (the deployment copy must use the corresponding module filename) and keep the SQLite database at mode `0600`.

After HMAC, event and repository verification, a valid `X-GitHub-Delivery` UUID is reserved in a durable SQLite transaction **before** `systemctl start`. Repeated accepted deliveries return 200 without another wake; concurrent attempts and interrupted/uncertain effects fail closed with 503 and retain their pending claim. A repeated UUID with changed content is refused. Only confirmed accepted records expire after 30 days, and the maximum 20,000-entry ledger holds new requests when full rather than deleting uncertain reservations. The existing five-minute independent GitHub polling remains the recovery mechanism, not a blind delivery replay. Never assume a webhook acknowledgment means a job executed.

**Rollout gate:** this change is not present in the running webhook receiver until a reviewed release installs the module, provisions the owner directory, verifies service restrictions and tests real GitHub redelivery, restart and readback. The current production receiver remains untouched.
