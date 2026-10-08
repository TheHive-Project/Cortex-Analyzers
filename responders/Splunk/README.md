### Splunk Enterprise Security Notable Status Sync

`SplunkES_NotableStatusSync` mirrors a TheHive case/alert stage onto the matching Splunk Enterprise Security notable event(s), via Splunk ES's [`notable_update`](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference) REST endpoint. It runs on `thehive:case` / `thehive:alert`.

Named after the Splunk-side entity it updates (a *notable event*), not "alert" — Splunk's native Alert feature is a different thing.

#### Notable event ID source

1. If `custom_field_name_notable_event_id` is set, the responder reads that custom field. **Recommended**, and required when running on a **case**.
2. Otherwise it falls back to TheHive's native `sourceRef`, which needs no extra configuration but exists only on alerts, not cases.

Either source may hold one `ruleUID` (format `{UUID}@@notable@@{hash}`, as shown in Splunk ES) or a comma-separated list; merged-alert cases producing a list are handled automatically. Each notable event is updated independently, so one stale `ruleUID` can't block the others — the report lists which succeeded and which failed.

#### Status mapping

Splunk ES status IDs are defined per-instance in `reviewstatuses.conf`, so they are configurable. Defaults match Splunk ES's factory statuses:

| TheHive stage | Config item | Default |
|---|---|---|
| New | `status_id_new` | `1` (New) |
| InProgress | `status_id_in_progress` | `2` (In Progress) |
| Imported | `status_id_in_progress` | `2` (In Progress) |
| Closed | `status_id_closed` | `5` (Closed) |

If your instance customized `reviewstatuses.conf`, check **Enterprise Security > Configure > Incident Management > Incident Review Settings** for the IDs in use.

#### Audit trail and ownership

Every update sends an auto-generated `comment` (object type, title, new stage, triggering user) so the status change is recorded.

Enabling `sync_owner` also sets the notable's `newOwner` to the case/alert assignee. **Off by default** — TheHive logins and Splunk usernames are separate identity spaces; only enable it once you've confirmed they align.

#### Setup

- Authenticate with either an `auth_token` (Splunk 7.3+ Bearer token, token auth enabled on the instance) or `username`/`password` — one or the other.
- Whichever identity is used needs the **`ess_analyst`** role and **`edit_notable_events`** capability.
- Use the Splunk **management port** (default `8089`), not the web UI port.
- Populate `custom_field_name_notable_event_id`'s field with the notable event's `ruleUID` at import time.
