## Pseudocode: crates/ledger/src/offer.rs

"Offer sorting and comparison utilities for the Stellar DEX."

"Offers are ordered by:
 1. Price (ascending) — lower price is better
 2. Offer ID (ascending) — older offers have FIFO priority"

### OfferDescriptor (struct)

```
STRUCT OfferDescriptor:
  price    { n, d }   // rational price n/d
  offer_id            // unique offer identifier
```

### OfferDescriptor::from_offer_entry

```
FUNCTION from_offer_entry(offer):
  → OfferDescriptor { price: offer.price, offer_id: offer.offer_id }
```

### OfferDescriptor::from_ledger_entry

```
FUNCTION from_ledger_entry(entry):
  ASSERT: entry.data is an Offer
  → from_offer_entry(entry.data.offer)
```

### OfferDescriptor::price_as_f64

```
FUNCTION price_as_f64(self):
  → self.price.n / self.price.d   // floating-point, comparison only
```

### OfferDescriptor ordering

```
FUNCTION compare(self, other):
  "Compare by price first (lower is better)"
  self_price  = self.price_as_f64()
  other_price = other.price_as_f64()

  if self_price == other_price (or incomparable):
    "For equal prices, lower offer ID is better (older first)"
    → compare self.offer_id vs other.offer_id
  else:
    → compare self_price vs other_price
```

### OfferDescriptor equality

```
FUNCTION equals(self, other):
  → self.price.n == other.price.n
    AND self.price.d == other.price.d
    AND self.offer_id == other.offer_id
```

NOTE: Equality checks exact n/d — not the ratio. 1/2 != 2/4.

### <a id="is_better_offer"></a>is_better_offer

```
FUNCTION is_better_offer(lhs, rhs):
  → lhs < rhs   // uses OfferDescriptor ordering
```

### is_better_offer_entry

```
FUNCTION is_better_offer_entry(lhs_entry, rhs_entry):
  lhs_desc = OfferDescriptor::from_ledger_entry(lhs_entry)
  rhs_desc = OfferDescriptor::from_ledger_entry(rhs_entry)
  → is_better_offer(lhs_desc, rhs_desc)
```

**Calls**: [is_better_offer](#is_better_offer)

### AssetPair (struct)

```
STRUCT AssetPair:
  buying   // the asset being bought
  selling  // the asset being sold
```

### AssetPair hashing

```
FUNCTION hash(self):
  hash XDR-encoded bytes of self.buying
  hash XDR-encoded bytes of self.selling
```

### IsBetterOfferComparator

```
FUNCTION compare(self, lhs, rhs):
  → is_better_offer(lhs, rhs)
```

**Calls**: [is_better_offer](#is_better_offer)

### sort_offers

```
FUNCTION sort_offers(offers):
  sort offers by OfferDescriptor ordering
  "Better offers (lower price, or same price with lower ID) come first"
```

### sort_offer_descriptors

```
FUNCTION sort_offer_descriptors(offers):
  sort offers using natural OfferDescriptor ordering
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 252    | 55         |
| Functions     | 13     | 11         |
