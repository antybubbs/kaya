# Table export

Kaya's shared table enhancer adds **Export** immediately before **Table settings** on applicable user-facing data tables. The menu offers UTF-8 CSV and tab-delimited text. Both formats include headers, the rows matching the current table state, and only columns currently enabled in Table settings. Selection, action, control-only and unlabelled columns are omitted.

CSV is intended for Excel, LibreOffice and analysis tools. It includes a UTF-8 byte-order mark, quotes commas/quotes/line breaks correctly, and prefixes values beginning with `=`, `+`, `-`, `@`, tab or carriage return to prevent spreadsheet formula execution. Text export uses tabs and CRLF row endings and replaces embedded row/tab characters with spaces. Empty values remain blank.

Browser-backed tables export the complete authorized result set already rendered for the current server query, after client-side filters and sorting. Server-paginated Audit Logs, User Management, DNS retained clients/leases, and IP/WAN performance/check history use authenticated backend endpoints. Those endpoints reuse the table filters, ignore page controls, validate format and column names against server-owned allowlists, apply the same module/role checks as the page, and produce redacted export audit events. Audit and DNS retained exports are limited to 100,000 matching rows; raw IP/WAN checks retain the existing 10,000-observation selected-range bound. Narrow filters before retrying a larger export.

Exports are downloads, not a new permission boundary. Ordinary tables use their existing view permission. Administrative exports still require administrator access, and module exports still require module allocation. GET is used because exporting does not mutate application data; no CSRF exception is introduced for a state-changing action. Responses use `no-store`, do not log row contents, and do not accept arbitrary model field names or SQL expressions.

## Developer convention

Place genuine data tables within `.content`, provide a stable `data-table-key`, and identify columns with `data-col`. Use `data-col="actions"`, `data-col="select"`, `class="action-col"`, or `data-export="false"` on a header for fields that must not leave the UI. Never expose a secret merely because its masked control is visible.

For a bounded table whose complete query result is rendered, no module JavaScript is required. The shared enhancer exports readable text from badges, links, dates and form controls and uses the current visible-column state.

For server pagination or a potentially large result, set `data-export-url` on the table and implement one permission-checked endpoint using `app.services.table_export`. The endpoint must:

- reuse the page's query builder and row/object authorization;
- validate requested columns with `validate_export_columns` and map only approved display fields;
- accept only `csv` and `text`;
- remove pagination without removing filters or sorting;
- stream or enforce and document a safe result bound;
- create a redacted audit event for administrative, security or sensitive datasets; and
- return a safe error without query, path, secret or row contents.

Do not enable this generic framework for Secure Vault, Secure Send package/recipient data, live authentication-session or linked-identity inventories, credential fields, password/TOTP material, encrypted values, tokens, recovery data, recording contents, attachment contents, or control/layout tables. Those datasets require a purpose-built threat model and export workflow.

## Coverage audit

| Area / table | Shared behavior | Export source / note |
|---|---|---|
| Asset Manager, asset attachments | Automatic | Complete rendered authorized query; action links excluded |
| Backup Manager (Proxmox jobs, Docker workloads/jobs, manual backups) | Automatic | Complete rendered bounded operational query; controls excluded |
| VM/Docker Manager workloads and host workloads | Automatic | Complete rendered bounded inventory query |
| Domain Manager and domain history | Automatic | Complete rendered bounded query |
| VLAN/IP Manager records, observed DNS clients, DHCP history and record detail histories | Automatic | Complete rendered authorized query; page category/search state retained |
| License Keys | Automatic | Visible enabled columns only; actions excluded; generic table does not add hidden model fields |
| Runbook library, spaces and tags | Automatic | Visible enabled columns; editor forms/actions excluded |
| DNS query log, local DNS, blocklists and investigations | Automatic | Provider response already bounded/rendered by the current query |
| DNS retained clients and DHCP leases | Backend | Full filtered server result, server allowlist, DNS module permission, audit, 100,000-row bound |
| IP/WAN performance and raw checks | Backend | Full selected/filtered server result within documented retention bounds, sort preserved, module permission and audit |
| Audit Logs | Backend | Administrator only; all filtered pages, allowlisted display fields, audit; inspector metadata/user-agent omitted |
| User Management | Backend | Administrator only; approved visible account metadata, audit; password hashes, TOTP secrets and session material omitted |
| Categories and custom-field definitions | Automatic | Current module/list context; mutation controls excluded |
| HA cluster list | Automatic | Cluster overview fields only; Open control excluded |
| Runtime package versions | Automatic | Non-secret runtime inventory |
| Remote Manager recording index | Automatic | Recording metadata visible to the authorized page; media/content and actions excluded |
| Site VLAN and DHCP administration | Automatic | Current visible configuration values; mutation controls excluded |
| Notifications | Excluded | The centre is an actionable article feed, not a data table |
| Static administration navigation / summary layouts | Excluded by convention | Not meaningful datasets |
| Secure Vault table | Excluded | Generic export is forbidden by the Vault encryption/authentication design |
| Secure Send tables | Excluded | Decrypted recipient/package summaries require a separate audited export design |
| Active sessions and linked OIDC identities | Excluded | Security-sensitive session/identity inventory requires a dedicated audited design |
