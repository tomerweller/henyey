---
name: simplify
description: Review or apply code simplifications to a crate
argument-hint: <crate-path> [--apply]
---

Read the prompt file at `prompts/simplify.md` and follow its instructions.

Parse `$ARGUMENTS`:
- The first argument is the crate path. Replace `$TARGET` with it.
- If `--apply` is present, set `$MODE = apply`. Otherwise set `$MODE = review`.
