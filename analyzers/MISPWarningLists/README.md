### MISPWarningLists 
[MISPWarningLists](https://github.com/MISP/misp-warninglists) are lists of well-known indicators that can be associated to potential false positives, errors or mistakes.

The analyzer comes in a single flavour that will check observables against MISP Warninglists to filter false positives.

#### Requirements
Option 1 low performances:
 - Clone  the [MISPWarningLists](https://github.com/MISP/misp-warninglists) GitHub repository.
 - In the analyzer parameters configure the `path` of WarningLists folder.

Option 2 high performances:
 - Clone  the [MISPWarningLists](https://github.com/MISP/misp-warninglists) GitHub repository.
 - Install [PostgreSQL](https://www.postgresql.org/) database.
 - Set `conn_string` and `warninglists_path`  located inside script `warninglists_create_db.py`  and run it in order to parse all MISPWarningLists and insert into PostgreSQL.
 - In the analyzer parameters configure the `conn` to DB (for example: postgresql+psycopg2://user:password@localhost:5432/warninglists').
