### IVRE

Get intelligence from an [IVRE](https://ivre.rocks/) instance.

#### Requirements

You need an access to an IVRE instance. Unlike most analyzers, IVRE
does not exist as a public service but is an open-source tool: you
need to install and run your own instance. The repository is [on
GitHub](https://github.com/cea-sec/ivre).

To learn more about IVRE (and its "purposes"), you can read the
documentation, particularly about [the
principles](https://doc.ivre.rocks/en/latest/overview/principles.html),
and some [use
cases](https://doc.ivre.rocks/en/latest/usage/use-cases.html).

Supply the following parameters to the analyzer in order to use it:

- `db_url` (string): the IVRE instance database URL (format: same as IVRE's
  configuration; default: use IVRE's configuration)
- `db_url_data` (string): the IVRE instance database URL for the data purpose
  (idem)
- `db_url_passive` (string): the IVRE instance database URL for the passive purpose
  (idem)
- `db_url_scans` (string): the IVRE instance database URL for the scans purpose
  (idem)
- `use_data` (boolean): should the analyzer use the data purpose?
- `use_passive` (boolean): should the analyzer use the passive purpose?
- `use_scans` (boolean): should the analyzer use the scans purpose?

