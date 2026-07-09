# Licence Manager Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

Licence Manager stores licence and product key information.

## Routes

- `/security/license-keys`

## Models Used

- `Licence`
- `CustomField`
- `CustomFieldValue`
- `ManagedListItem`

## Workflows

- List/search/filter licences.
- Create/edit licences.
- Mark favourites.
- Store encrypted product keys.
- Reveal product keys.
- Import/export licence CSV.

## Permissions

- Read requires authenticated user.
- Create/edit/reveal requires editor.
- Import/export requires admin.

## Settings And Dependencies

- Managed list for licence type.
- Custom fields for `licences`.

## Edge Cases And Risks

- Admin CSV export decrypts product keys into the exported file.
- Product key reveal is audited but still exposes sensitive material to editors.
