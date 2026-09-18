## 2024-05-19 - Keyboard Navigation for Custom Sidebar Links
**Learning:** In SPAs using plain `<a>` tags with `data-*` attributes for routing, missing `href` attributes make navigation completely inaccessible via keyboard because they are omitted from the document's tab order by browsers.
**Action:** Always ensure navigation elements are semantic. Add `href="#hash"` to anchor tags to make them focusable, and combine with `e.preventDefault()` in JS event listeners to handle routing while preserving accessibility and focus management. Add `:focus-visible` styles to complete the experience.

## 2024-05-20 - Explicit Label Associations and Icon-Only Buttons
**Learning:** In vanilla HTML/JS applications, failing to explicitly associate `<label>` elements with their inputs using the `for` attribute and an input `id` makes forms significantly harder to use for screen reader users and users who rely on clicking labels to focus inputs. Additionally, icon-only buttons (like `✕` for closing a modal) completely lack context for screen readers unless an `aria-label` (like `aria-label="Fechar"`) is provided.
**Action:** Always verify that `<label>` tags use the `for` attribute referencing the exact `id` of the form control, and always add `aria-label` attributes to any button that uses only an icon or symbol as its visual content.
