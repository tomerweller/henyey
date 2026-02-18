## Pseudocode: crates/scp/src/compare.rs

"Ordering and comparison functions for SCP statements and ballots."

### is_newer_nomination_or_ballot_st

"Returns true if new_st is newer than old_st for the same node."
"Used to determine if a statement should replace an existing one."

```
function is_newer_nomination_or_ballot_st(old_st, new_st):
  type_rank = pledge type → rank:
    Nominate → 0, Prepare → 1, Confirm → 2, Externalize → 3

  old_rank = type_rank(old_st.pledges)
  new_rank = type_rank(new_st.pledges)

  if old_rank != new_rank:
    → new_rank > old_rank

  if both Nominate:
    → is_newer_nominate(old, new)
  if both Prepare:
    → is_newer_prepare(old, new)
  if both Confirm:
    → is_newer_confirm(old, new)
  if both Externalize:
    → false
  → false
```

### Helper: is_newer_nominate

```
function is_newer_nominate(old, new):
  old_votes = set of old.votes
  old_accepted = set of old.accepted
  new_votes = set of new.votes
  new_accepted = set of new.accepted

  GUARD old_votes is NOT subset of new_votes → false
  GUARD old_accepted is NOT subset of new_accepted → false

  → new_votes.size > old_votes.size
    OR new_accepted.size > old_accepted.size
```

### Helper: cmp_opt_ballot

```
function cmp_opt_ballot(a, b):
  if both absent:  → Equal
  if a absent:     → Less
  if b absent:     → Greater
  → compare(a.counter, b.counter)
      then compare(a.value, b.value)
```

### Helper: is_newer_prepare

```
function is_newer_prepare(old, new):
  compare new.ballot.counter vs old.ballot.counter:
    if Greater → true
    if Less   → false

  compare cmp_opt_ballot(old.prepared, new.prepared):
    if Less    → true
    if Greater → false

    compare cmp_opt_ballot(old.prepared_prime, new.prepared_prime):
      if Less    → true
      if Greater → false
      → new.n_h > old.n_h
```

### Helper: is_newer_confirm

```
function is_newer_confirm(old, new):
  compare new.ballot.counter vs old.ballot.counter:
    if Greater → true
    if Less   → false

  compare new.n_prepared vs old.n_prepared:
    if Greater → true
    if Less   → false

  → new.n_h > old.n_h
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 99     | 53         |
| Functions    | 5      | 5          |
