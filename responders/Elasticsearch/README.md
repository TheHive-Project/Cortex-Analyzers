### Elastic Security Alert Status Sync

`ElasticSecurity_AlertStatusSync` mirrors a TheHive case/alert stage onto the matching Elastic Security detection alert(s), via Kibana's [detection alert status](https://www.elastic.co/docs/api/doc/kibana/operation/operation-setalertsstatus) API. It runs on `thehive:case` / `thehive:alert`.

It targets **Kibana**, not Elasticsearch (that's the `Elasticsearch_Analysis` analyzer) — different URL and credentials, hence the separate `ElasticSecurity` baseConfig.

#### Alert ID source

1. If `custom_field_name_alert_id` is set, the responder reads that custom field. Required when running on a **case**.
2. Otherwise it falls back to TheHive's native `sourceRef`. This works for alerts imported by Elastic's stock TheHive connector (it sets `sourceRef` to the alert UUID, which equals the detection alert `_id`), but `sourceRef` does not exist on cases.

Either source may hold one `_id` or a comma-separated list; merged-alert cases producing a list are handled automatically.

We recommend using custom fields, which is `elastic-alert-uuid` by default.

#### Status mapping

Elastic's status enum is fixed (`open`, `acknowledged`, `in-progress`, `closed`); which one each TheHive stage means is configurable:

| TheHive stage | Config item | Default |
|---|---|---|
| New | `status_new` | `open` |
| InProgress | `status_in_progress` | `in-progress` |
| Imported | `status_imported` | `in-progress` |
| Closed | `status_closed` | `closed` |

#### Closing reasons

When the resulting status is `closed`, a reason is sent (Elastic ignores it otherwise). The `reason_map` config item holds the full `TheHiveStatus:elastic_reason` mapping, pre-filled with:

| TheHive status | Elastic reason |
|---|---|
| FalsePositive | `false_positive` |
| TruePositive | `true_positive` |
| BenignPositive | `benign_positive` |
| Duplicated / Duplicate | `duplicate` |
| Indeterminate / Ignored / Other | `other` |

Edit, add or remove pairs as needed (for example, `Contained:true_positive` for a custom status). Unmapped statuses fall back to `default_close_reason` (`other`). Clearing `reason_map` entirely restores the built-in defaults. Elastic's own reasons are `false_positive`, `duplicate`, `true_positive`, `benign_positive`, `automated_closure` and `other`, but any string up to 1024 chars is accepted.

#### Setup

- Create a Kibana API key that can write to Elastic Security alerts (`.alerts-security.alerts-*`), or use basic auth — one or the other, not both.
- `kibana_url` is the Kibana endpoint, not Elasticsearch. On Elastic Cloud these are different hostnames.
- Set `space_id` if alerts live in a non-default Kibana space.
- Populate `custom_field_name_alert_id`'s field with the Elastic alert `_id` at alert creation.
