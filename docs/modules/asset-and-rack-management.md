# Asset And Rack Management Modules

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Hardware Asset Manager

Purpose: track physical assets and related files/photos.

Routes:

- `/infrastructure/asset-manager`

Models:

- `HardwareAsset`
- `HardwareAssetAttachment`
- `CustomField`
- `CustomFieldValue`
- `ManagedListItem`

Workflows:

- List/search/filter assets.
- Create/edit assets.
- Upload photo.
- Upload/download attachments.
- Store custom fields.

Permissions:

- Read requires authenticated user.
- Create/update requires editor.

Settings/dependencies:

- Uses `max_upload_mb`.
- Uses managed lists for category, location, and status.
- Uses custom fields for `hardware_assets`.

Risks:

- Attachments are less strictly validated than photos.
- No malware scanning.
- Uploaded files are persistent under the uploads volume.

## Rack Manager

Purpose: model rack layout and mounted equipment.

Routes:

- `/infrastructure/rack-manager`

Models:

- `Rack`
- `RackItem`
- `HardwareAsset`

Workflows:

- Create racks.
- Add/edit/delete rack items.
- Drag/update layout.
- Associate rack items with hardware assets.
- Validate U height and overlap by mount side.

Permissions:

- Read requires authenticated user.
- Changes require editor.

Risks:

- Rack delete support is not prominent in current routing.
- Layout is UI-heavy and depends on JavaScript correctness.
