# RFCs

Draft design documents and discussion pieces for JAR.

**Files in this folder are drafts. They do not necessarily reflect concluded
design decisions.**

An RFC here may propose a direction, argue a position, or open a question for the
project to rule on. Its presence records that the discussion happened — not that
its recommendation was adopted. A document can sit here indefinitely, be
superseded, or be contradicted by whatever eventually ships. Read anything here
as a snapshot of thinking at the time it was written.

The normative design lives elsewhere:

- The formal specification is in [`spec/`](../spec).
- The decided distribution and review process is in [`docs/genesis.md`](../docs/genesis.md).

When an RFC's idea is actually adopted, that decision shows up in those sources —
not by promoting the RFC in place.

## Filing

- Copy [`0000-template.md`](0000-template.md) to `NNNN-short-title.md`, using
  the next free number.
- Any type of document is welcome: normative specifications, position papers,
  open questions, post-mortems.
- If — and only if — the RFC states normative requirements, it MUST include the
  Requirements Language section from the template, and the key words "MUST",
  "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
  "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" are then interpreted
  as described in BCP 14
  ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
  [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when,
  they appear in all capitals. Documents without that section carry no
  normative force.
- Keep the metadata table and Status History current; status changes are edits
  to the RFC, not new files.
