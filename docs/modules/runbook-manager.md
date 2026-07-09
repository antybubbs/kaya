# Runbook Manager Module

**Kaya version:** `dev`  
**Documentation version:** `dev`

## Purpose

Runbook Manager stores operational documentation, recovery steps, maintenance checklists, and internal service notes.

## Routes

- `/documentation/runbook-manager`

## Models Used

- `RunbookSpace`
- `RunbookPage`
- `RunbookPageHistory`
- `User`

## Workflows

- Create spaces.
- Create pages inside spaces.
- Edit pages.
- Delete pages.
- Search and filter pages by text, space, and tags.
- Switch between tile and table views.
- Render Markdown-like page content.
- Save page history before updates.

## Forms And Actions

- Space creation.
- Page creation.
- Page editing.
- Page deletion.
- Search/filter form.

## Permissions

- Read requires authenticated user.
- Create/update/delete requires editor.

## Dependencies

- Auth and role dependencies.
- Custom Markdown-like renderer in the router.
- Static JavaScript for editor behaviours.

## Edge Cases And Risks

- Markdown rendering is custom rather than a full Markdown library.
- Sanitisation relies on custom escaping/rendering logic.
- Version history exists, but full restore workflows are limited.
