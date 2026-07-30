# Accessibility Standard

## Target

Kaya should aim to meet WCAG 2.2 AA for its standard web interface.

Specialised remote-console content may have limitations imposed by the remote system, but Kaya's surrounding controls must remain accessible.

## Keyboard

All interactive controls must be keyboard reachable and operable.

Focus order must follow visual and logical order.

Do not remove visible focus indicators.

## Semantics

Use native HTML elements before custom widgets.

Buttons perform actions. Links navigate.

Headings must form a logical hierarchy.

Tables require proper headings.

## Labels and names

Every form control and icon-only button needs an accessible name.

Placeholder text is not a label.

## Colour and contrast

Text and essential controls must meet contrast requirements.

Status must not be communicated by colour alone.

Dark mode must be checked independently.

## Dynamic updates

Live status and validation updates should use appropriate ARIA live regions without creating excessive repeated announcements.

Loading indicators should communicate what is loading.

## Dialogs and menus

Dialogs must trap focus appropriately, announce their title and return focus on close.

Menus must support keyboard operation and not rely only on hover.

## Motion

Avoid unnecessary animation. Respect reduced-motion preferences.

## Testing

For substantial UI changes, perform:

- keyboard-only review;
- focus visibility check;
- accessible-name inspection;
- light and dark contrast check;
- responsive zoom check;
- automated accessibility scan where tooling exists.

Automated scans do not replace manual testing.
