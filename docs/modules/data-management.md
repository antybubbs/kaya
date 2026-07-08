# Data Management Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

This page covers import/export, custom fields, managed lists, and file upload behaviour.

## Import/Export

Routes:

- `/data/import-export`
- `/data/import-export/import/{module}`
- `/data/import-export/export/{module}`

Supported modules:

- Licences
- IP addresses

Models:

- `Licence`
- `IPAddress`
- `CustomFieldValue`
- Related custom field definitions

Permissions:

- Admin only.

Risks:

- Coverage is limited to licences and IP addresses.
- Licence export includes decrypted product keys.

## Custom Fields

Routes:

- `/data/custom-fields`

Supported modules:

- IP addresses
- Hardware assets
- Licences

Supported field types:

- Text
- Textarea
- Radio
- Select

Models:

- `CustomField`
- `CustomFieldValue`

Permissions:

- Admin only for field management.
- Module edit permissions for editing values.

Risks:

- Values use polymorphic entity references without database-level foreign keys.
- Field key and options must remain compatible with existing data.

## Categories / Managed Lists

Routes:

- `/data/categories`

Supported modules/lists:

- Hardware assets: category, location, status
- IP addresses: category
- Licences: licence type

Models:

- `ManagedListItem`

Permissions:

- Admin only for list management.

Risks:

- Existing records keep old text values if a list item is disabled or edited.

## File Uploads

Storage:

- General uploads: `/app/uploads`
- Hardware asset files: `/app/uploads/hardware_assets/{asset_id}`
- Remote recordings: `/app/data/remote-recordings/YYYY/MM/...`

Settings:

- `max_upload_mb`
- `max_recording_upload_mb`
- `min_recording_free_mb`

Risks:

- Hardware photos have magic-byte validation.
- Other attachments are less strict.
- No antivirus or content scanning.
- Recordings can contain credentials or sensitive session content.
