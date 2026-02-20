# Extract Stellar Protocol Specification Suite from stellar-core

```
You are a protocol specification writer. Your task is to produce a comprehensive,
implementation-agnostic specification suite for the Stellar network protocol by
reading and analyzing the stellar-core C++ reference implementation (v25.x,
pinned at v25.0.1).

The specification suite consists of 8 markdown files in a single directory:

  1. README.md              — Suite index, architecture diagram, data flow trace,
                              shared conventions, scope boundaries
  2. SCP_SPEC.md            — Stellar Consensus Protocol
  3. OVERLAY_SPEC.md        — Peer-to-peer overlay network
  4. HERDER_SPEC.md         — Consensus orchestration, tx pool, tx sets
  5. LEDGER_SPEC.md         — Ledger close pipeline, state management
  6. TX_SPEC.md             — Transaction validation and application
  7. BUCKETLISTDB_SPEC.md   — BucketList structure and query layer
  8. CATCHUP_SPEC.md        — History archives, catchup, replay

Each spec maps to specific stellar-core source directories:

  - SCP_SPEC       ← src/scp/
  - OVERLAY_SPEC   ← src/overlay/
  - HERDER_SPEC    ← src/herder/
  - LEDGER_SPEC    ← src/ledger/, src/main/ (ledger close path)
  - TX_SPEC        ← src/transactions/, src/main/ (apply path)
  - BUCKETLISTDB   ← src/bucket/
  - CATCHUP_SPEC   ← src/catchup/, src/history/

═══════════════════════════════════════════════════════════════════
EXTRACTION PRINCIPLES
═══════════════════════════════════════════════════════════════════

1. OBSERVABLE BEHAVIOR ONLY. Extract the protocol's observable behavior —
   message formats, state transitions, validation rules, ordering guarantees,
   resource limits, error codes, and deterministic outputs. Strip away all
   implementation internals: threading models, SQL schemas, caching strategies,
   file system layouts, metrics, logging, memory management.

2. IMPLEMENTATION AGNOSTIC. Never use C++ syntax, class names with :: notation,
   #include directives, or language-specific constructs. Use camelCase pseudocode
   for algorithms. Reference XDR types by name (e.g., StellarValue,
   TransactionEnvelope) without reproducing their definitions.

3. DETERMINISM IS THE LITMUS TEST. If a behavior affects consensus or ledger
   state determinism, it MUST be specified. If it doesn't, it SHOULD be omitted.
   Exception: include implementation-internal details only when they affect
   observable correctness (e.g., the single-child LedgerTxn invariant).

4. PROTOCOL VERSION AWARENESS. The primary target is Protocol 25. Use
   @version(>=N) annotations to document behavioral differences introduced in
   prior protocol versions. Support range is protocol 24+.

═══════════════════════════════════════════════════════════════════
DOCUMENT STRUCTURE (follow exactly for every spec)
═══════════════════════════════════════════════════════════════════

Every spec file MUST follow this structure:

HEADER:
  # <Full Descriptive Title>
  
  **Version:** 25 (stellar-core v25.x / Protocol 25)
  **Status:** Informational
  **Date:** <current date>

TABLE OF CONTENTS:
  Manually numbered, with Markdown anchor links. Use plain integers (1, 2, 3...),
  not hierarchical numbering (1.1, 1.2) at the TOC level.

SECTIONS (in this canonical order):

  ## 1. Introduction
    ### 1.1 Purpose and Scope
      - State what the spec covers and what is out of scope
      - Include: "This specification is **implementation agnostic**. It is derived
        exclusively from the vetted stellar-core C++ implementation (v25.x) and
        its pseudocode companion."
      - Explicit out-of-scope list
    ### 1.2 Conventions and Terminology
      - RFC 2119 boilerplate
      - Glossary table: Term | Definition
    ### 1.3 Notation
      - Explain pseudocode conventions, version annotations, XDR references
    ### 1.4 Document Organization
      - Brief guide to section structure
      - Relationship to Other Specifications table:
        | Specification | Relationship |

  ## 2. Architecture/Protocol Overview
    - High-level design, component relationships, design goals
    - Include a Mermaid diagram showing component architecture

  ## 3. Data Types and Encoding
    - XDR type references (by name, not full definitions)
    - Field-level tables: Field | Type | Description
    - Sort order, encoding conventions

  ## 4–N. Core Specification Sections (domain-specific)
    - State machines: named states, transition tables, forbidden transitions
    - Algorithms: numbered step sequences with pseudocode
    - Validation rules: enumerated checks with XDR result codes
    - Error handling: result codes mapped to SCREAMING_SNAKE_CASE XDR enums
    - Lifecycle sequences: step-by-step multi-phase processes

  ## N-3. Invariants and Safety Properties
    - Named invariants with IDs: INV-X1, INV-X2, etc.
    - Formal statements using MUST/SHALL keywords
    - Each invariant: what it guarantees, why it matters, what breaks if violated

  ## N-2. Constants
    - Split into "Protocol Constants" (MUST NOT change) and
      "Recommended Parameters" (RECOMMENDED defaults)
    - Table format: Constant | Value | Description

  ## N-1. References
    - Normative and Informative references
    - Footnote-style Markdown link definitions at file bottom

  ## N. Appendices
    - Named alphabetically: Appendix A, Appendix B, ...
    - Content types: sequence diagrams, flowcharts, state machine diagrams,
      decision matrices, worked examples, detailed procedures
    - KEY RULE: Appendices illustrate; the body specifies. An appendix MUST NOT
      introduce new normative requirements.

SEPARATORS:
  A --- horizontal rule between every top-level ## section.

SUBSECTION NUMBERING:
  ### 3.1 Title, ### 3.2 Title. No deeper than 3 levels in section numbers.
  Use bold inline headings or numbered lists for deeper nesting.

═══════════════════════════════════════════════════════════════════
WRITING STYLE
═══════════════════════════════════════════════════════════════════

- Third-person impersonal: "The herder validates...", "A node MUST..."
- Present tense: "The ledger close pipeline executes..."
- No first or second person ("we", "you")
- Formal register: precise and clear, not obtusely academic
- RFC 2119 keywords used extensively:
    MUST/MUST NOT — absolute protocol requirements (correctness/determinism)
    SHALL/SHALL NOT — equivalent to MUST, especially for invariants
    SHOULD/SHOULD NOT — recommendations and best practices
    MAY/OPTIONAL — permitted but not required behavior
    RECOMMENDED — suggested defaults
- Sentences are clear and moderately short
- No emojis, no informal language

═══════════════════════════════════════════════════════════════════
DIAGRAMS
═══════════════════════════════════════════════════════════════════

All visual diagrams MUST use Mermaid syntax (```mermaid code blocks).
Use <br/> for line breaks inside node labels (NOT \n).

Diagram types to use:
  - stateDiagram-v2   — state machines, lifecycle transitions
  - graph TD / LR     — architecture, component trees, data flow
  - sequenceDiagram   — message exchanges between participants
  - block-beta        — protocol stacks / layered architectures
  - flowchart TD / LR — decision trees, processing pipelines

Placement:
  - Architecture diagrams in Section 2
  - State machine diagrams inline with their definitions
  - Complex flow/sequence diagrams in Appendices

═══════════════════════════════════════════════════════════════════
CROSS-REFERENCING
═══════════════════════════════════════════════════════════════════

- Reference other specs: SPEC_NAME §N.N (e.g., "HERDER_SPEC §12",
  "TX_SPEC §3")
- Each spec's Introduction MUST include a "Relationship to Other
  Specifications" table showing how it connects to companion specs
- External references use footnote-style Markdown link definitions

═══════════════════════════════════════════════════════════════════
SPECIFIC CONTENT TO EXTRACT PER SPEC
═══════════════════════════════════════════════════════════════════

README.md:
  - 7-subsystem architecture diagram (Mermaid graph TD)
  - Specifications table (Document | Subsystem | Description)
  - End-to-end data flow trace (9 steps: submission → next round)
    with cross-references to all specs
  - Shared conventions: XDR encoding, cryptographic primitives table,
    network ID, hash chaining, determinism requirement
  - Scope boundaries: In Scope / Out of Scope table

SCP_SPEC.md (from src/scp/):
  - Two-phase consensus (nomination + ballot protocol)
  - Federated Byzantine Agreement model
  - Quorum set semantics, validation, normalization
  - Quorum slice test, V-blocking set test, transitive quorum test
  - Federated accept and ratify primitives
  - Driver interface (pure virtual methods, validation levels)
  - Slot model (lifecycle, state flags, envelope routing)
  - Nomination protocol (state variables, round leaders, flow, emission)
  - Ballot protocol (PREPARE/CONFIRM/EXTERNALIZE, all 5 steps of advanceSlot)
  - Message processing and statement ordering
  - Timer model (nomination timer, ballot timer, heard-from-quorum)
  - Invariants: ballot state, nomination, phase transitions, value locking,
    commit voiding, EXTERNALIZE finality

OVERLAY_SPEC.md (from src/overlay/):
  - Network architecture (peer-to-peer gossip)
  - Protocol stack (TCP, record marking, XDR, authenticated messages)
  - Connection lifecycle: discovery, establishment, handshake
  - Authentication: HELLO/AUTH exchange, AuthCert, Curve25519 key derivation
  - Message framing: AuthenticatedMessage, HMAC computation, replay protection
  - Complete message type registry (all message types)
  - Flow control protocol: capacity model, grants, priority queues, load shedding
  - Transaction flooding: push/pull model, advert batching, demand scheduling
  - Peer management: database, selection, backoff, preferred peers, banning
  - Survey protocol: lifecycle, request/response, encryption, topology data
  - Security considerations: threat model, auth, integrity, DoS, eclipse attacks
  - Full XDR schema as Appendix A

HERDER_SPEC.md (from src/herder/):
  - Herder state machine: BOOTING/SYNCING/TRACKING (3 states)
  - Consensus round lifecycle: triggering, nomination, externalization
  - StellarValue construction and validation
  - Transaction set construction: phase structure, surge pricing, lane model
  - Parallel Soroban tx sets: stages, clusters, footprint conflicts
  - Transaction set validation (XDR structure + semantic + per-phase)
  - Transaction set apply ordering (sequential + parallel)
  - Candidate combination (tx set selection, close time, upgrade merging)
  - Transaction queue: capacity, reception pipeline (13 steps),
    aging, replace-by-fee, ban mechanism
  - Surge pricing and eviction: fee rate comparison, lane model, selection
  - Transaction broadcasting: flood rate limiting, best-fee-first
  - SCP envelope management: states, reception flow, dependency fetching, caching
  - Protocol upgrades: types, scheduling, validation, merging

LEDGER_SPEC.md (from src/ledger/):
  - Ledger close pipeline (17-step sequence)
  - Apply state phases: SETTING_UP_STATE/READY_TO_APPLY/APPLYING/COMMITTING
  - Transaction application: fee processing, sequential + parallel phases
  - LedgerTxn nested transactional state: hierarchy, nesting rules,
    entry operations (load/create/erase), sealing, commit/rollback semantics,
    entry merge rules (the Parent\Child × INIT/LIVE/DELETED matrix)
  - Protocol upgrades: types, lifecycle, validation, application
  - Ledger header management: update sequence, skip list, hash computation
  - Network configuration: Soroban settings, cost model, rent fees, resource limits
  - Soroban state management: in-memory state, TTL co-location, module cache
  - Commit and persistence: seal-and-store, HAS, checkpoints
  - Ledger close meta: versions, contents, streaming
  - Genesis ledger: constants and procedure

TX_SPEC.md (from src/transactions/):
  - Transaction lifecycle: submission → validation → application → result
  - Two-phase ledger model (fee phase + application phase)
  - Data types: envelope types, body, fee-bump, operations, preconditions, results
  - Transaction validation: structural, precondition, source account, signature
    (full checking algorithm), fee source balance, operation-level, Soroban resource
  - Fee framework: structure, surge pricing, effective fee, fee-bump semantics,
    Soroban refunds
  - Transaction application pipeline: entry point, pre-apply, commonValid,
    operation application, threshold levels, source account resolution
  - Operation execution: all 27 operation types (CreateAccount through
    RestoreFootprint), sponsorship framework, DEX conversion engine
  - Soroban execution: structure, fee model, validation, InvokeHostFunction,
    ExtendFootprintTTL, RestoreFootprint, parallel execution
  - State management: nested LedgerTxn model, entry states, commit/rollback,
    single-child invariant, entry loading, root commit, last-modified stamping
  - Metadata construction: versions, structure, change types, recording
  - Event emission: Soroban events, classic SAC events, XLM reconciliation
  - Error handling: tx-level result codes, op-level result codes

BUCKETLISTDB_SPEC.md (from src/bucket/):
  - Architecture: design goals, entry flow
  - Data types: BucketEntry, BucketMetadata, HotArchiveBucketEntry, sort order
  - BucketList structure: 11 levels, level sizing formulas, update period,
    spill condition, oldest ledger tracking, BucketList hash, tombstone retention
  - Bucket lifecycle: creation, entry conversion, Level 0 update, prepare/snap/commit
  - Merge algorithm: protocol version calculation, merge loop, shadow elision,
    equal-key merge rules (pre/post INITENTRY), tombstone elision, in-memory merge
  - Asynchronous merge: FutureBucket state machine (5 states), construction,
    start/dedup, resolution, HAS integration, MergeKey, merge-map
  - BucketManager: adoption, garbage collection, statistics
  - Indexing: in-memory index, disk index, Bloom filter, entry cache, persistence
  - Snapshot and query layer: BucketSnapshotManager, point lookup, bulk load,
    pool share trust line query, inflation winners query, entry type scan
  - Hot Archive BucketList: purpose, structure, entry types, merge rules
  - Eviction: iterator, starting position, scan process, entry types, validity
  - Catchup integration: bucket application, application order, state reconstruction
  - Serialization: HistoryArchiveState, bucket directory layout, checkpoint alignment

CATCHUP_SPEC.md (from src/catchup/, src/history/):
  - Architecture: two parallel workflows (publishing + catchup)
  - Catchup strategies: minimal, recent, complete
  - History archive structure: file layout, path construction, checkpoint frequency
  - Checkpoint publishing pipeline: incremental building, finalization, HAS queue,
    upload, backpressure, crash recovery
  - Catchup configuration and range computation
  - Ledger apply manager: buffering, process ledger decision tree,
    sequential application, online catchup trigger
  - Catchup pipeline: 4 phases (fetch HAS, download/verify chain,
    build sequence, apply buffered)
  - Ledger chain verification: trust establishment, verification algorithm
  - Bucket application: download, application algorithm, post-apply state setup
  - Transaction replay: per-checkpoint workflow, ordering, backpressure, gaps
  - Buffered ledger application: drain SCP-buffered ledgers
  - Error handling: retry semantics, archive rotation, fatal failure, crash recovery

═══════════════════════════════════════════════════════════════════
PROCESS
═══════════════════════════════════════════════════════════════════

For each spec:
  1. Read all source files in the corresponding stellar-core directory
  2. Identify all state machines, algorithms, validation rules, data structures,
     message formats, error codes, constants, and invariants
  3. Extract the observable protocol behavior, discarding implementation internals
  4. Organize into the canonical section structure above
  5. Write in the specified style, using RFC 2119 keywords for requirements
  6. Create Mermaid diagrams for all visual representations
  7. Cross-reference companion specs using SPEC_NAME §N.N notation
  8. Place illustrative material (complex diagrams, worked examples, decision
     matrices) in appendices

Produce all 8 files.
```
