---
name: parity-check
description: Analyze or update a crate's PARITY_STATUS.md for stellar-core parity
argument-hint: <crate-path> [--apply]
---

Read the prompt file at `prompts/parity-check.md` and follow its instructions.

Parse `$ARGUMENTS`:
- The first argument is the crate path. Replace `$TARGET` with it.
- If `--apply` is present, set `$MODE = apply`. Otherwise set `$MODE = review`.
