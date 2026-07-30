# UI Design Standard

## Purpose

Kaya's interface should be consistent across modules and clear during normal, degraded and failed states.

## Shared layout

Use the established application shell, navigation, page heading and toolbar patterns.

Do not introduce module-specific spacing systems, button styles or card structures without a reusable design-system change.

## Page structure

A standard module page should contain:

1. page title and concise description where useful;
2. primary actions;
3. search, filter or status controls;
4. main content;
5. empty, loading or error state;
6. pagination or history controls where required.

## Toolbars

Search and primary actions should follow one shared layout.

Primary creation actions should be easy to locate and should not move unpredictably between modules.

On narrow screens, controls may stack while preserving a logical tab order.

## Cards and host blocks

Cards must communicate status through more than colour alone.

For operational host blocks:

- healthy state may use the approved green treatment;
- warning or threshold breach may use amber;
- offline or failed state should use a clearly visible red treatment;
- unknown or stale state should use a neutral treatment distinct from healthy.

Text labels and icons must accompany colour.

A live status bar should align fully with the card's intended content width and must not end prematurely due to nested padding.

## Forms

Every field needs a visible label.

Use help text for unfamiliar settings and explain consequences before destructive or security-sensitive options.

Validation errors should appear near the affected field and include a page-level summary where useful.

Do not use placeholder text as the only label.

## Buttons

Use one primary action per local decision area.

Destructive actions require the destructive style and confirmation proportionate to impact.

Disabled buttons should explain why through nearby text or accessible description when the reason is not obvious.

## Tables

Tables need:

- meaningful headings;
- stable alignment;
- responsive handling;
- clear empty state;
- accessible row actions;
- pagination for large datasets.

Do not hide essential data solely on mobile. Use stacked rows, priority columns or detail expansion.

## Dark mode

All components must be tested in light and dark modes.

Do not hardcode black text, white backgrounds or isolated colours.

Use design tokens or existing CSS variables.

Dropdowns, overlays, menus, charts and browser-native controls require specific dark-mode checks.

## Feedback

Every mutation should provide a clear result.

Use:

- inline validation for form errors;
- toast or banner messages for successful actions;
- persistent warning banners for ongoing risk;
- progress indicators for operations that take noticeable time.

Do not show success before the server has confirmed completion.

## Empty and stale states

An empty state should explain whether:

- no records exist;
- filters removed all results;
- data has never been collected;
- the collector failed;
- the module is not configured.

Stale operational data must display its last update time and must not look current.

## Responsive behaviour

Interfaces must remain usable at common mobile widths.

Avoid fixed-width content that causes horizontal page scrolling.

Remote-console screens may use specialised responsive behaviour to maximise console space, but other controls must remain reachable.

## Accessibility

Follow the Accessibility Standard.

Interactive elements must be keyboard reachable, labelled and visibly focused.

Status must not rely on colour alone.

## Content style

Use clear language aimed at self-hosting and infrastructure users.

Avoid unexplained internal implementation terminology in the UI.

Confirmations should describe the actual consequence, not merely ask “Are you sure?”
