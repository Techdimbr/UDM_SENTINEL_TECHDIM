## 2024-05-19 - Keyboard Navigation for Custom Sidebar Links
**Learning:** In SPAs using plain `<a>` tags with `data-*` attributes for routing, missing `href` attributes make navigation completely inaccessible via keyboard because they are omitted from the document's tab order by browsers.
**Action:** Always ensure navigation elements are semantic. Add `href="#hash"` to anchor tags to make them focusable, and combine with `e.preventDefault()` in JS event listeners to handle routing while preserving accessibility and focus management. Add `:focus-visible` styles to complete the experience.
