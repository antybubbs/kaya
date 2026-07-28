# Categories and Custom Fields Navigation Inventory

This inventory records the implemented module consumers before navigation is exposed. It is intentionally limited to working routes and persisted data already used by module forms and records.

| Module | Categories | Custom Fields | Existing Routes | Existing Permissions | Action |
| --- | --- | --- | --- | --- | --- |
| Asset Manager | Yes: category, location, status | Yes | `/data/categories?module=hardware_assets`; `/data/custom-fields?module=hardware_assets` | Admin role plus `asset_manager` module allocation | Add both links to the module navigation bar |
| VLAN/IP Manager | Yes: category | Yes | `/data/categories?module=ip_addresses`; `/data/custom-fields?module=ip_addresses` | Admin role plus `vlan_ip_manager` module allocation | Add both links to the module navigation bar and remove the duplicate category editor from central module configuration |
| License Keys | Yes: license type | Yes | `/data/categories?module=licences`; `/data/custom-fields?module=licences` | Admin role plus `licence_manager` module allocation | Add both links to the module navigation bar |

No other registered module currently consumes `ManagedListItem`, `CustomField`, or `CustomFieldValue` through an implemented module workflow, so no other navigation item is added.

The existing `/data/categories` and `/data/custom-fields` GET and POST routes remain the canonical management routes. They require the admin role, validate the selected internal module against a fixed mapping, enforce the corresponding per-user module allocation, validate CSRF on mutations, and enforce object-level module access before changing or deleting an existing row.
