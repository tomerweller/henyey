## Pseudocode: crates/tx/src/state/offer_index.rs

### Data Structures

```
STRUCT OfferDescriptor:
    price: Price (n/d ratio)
    offer_id: i64

STRUCT OfferKey:
    seller: bytes[32]
    offer_id: i64

STRUCT AssetPair:
    buying: AssetKey
    selling: AssetKey

STRUCT OfferIndex:
    "Order books keyed by (buying, selling) asset pair"
    order_books: Map<AssetPair, SortedMap<OfferDescriptor, OfferKey>>
    "Reverse index: offer key -> (asset pair, descriptor) for efficient removal"
    offer_locations: Map<OfferKey, (AssetPair, OfferDescriptor)>
```

### OfferDescriptor ordering

"Use floating-point comparison to match stellar-core behavior."
"stellar-core uses double(price.n) / double(price.d) for ordering."

```
compare(self, other):
    self_price = float(self.price.n) / float(self.price.d)
    other_price = float(other.price.n) / float(other.price.d)
    if prices are equal or incomparable:
        → compare by offer_id ascending
    else:
        → compare by price ascending
```

NOTE: Lower price = better offer. Ties broken by lower offer_id.

### add_offer

```
add_offer(offer):
    key = OfferKey from offer
    descriptor = OfferDescriptor from offer
    asset_pair = AssetPair(offer.buying, offer.selling)

    order_book = order_books[asset_pair] (create if absent)
    order_book[descriptor] = key

    offer_locations[key] = (asset_pair, descriptor)
```

### remove_offer

```
remove_offer(seller, offer_id):
    key = OfferKey(seller, offer_id)
    remove_by_key(key)
```

### remove_by_key

```
remove_by_key(key):
    if key in offer_locations:
        (asset_pair, descriptor) = offer_locations.remove(key)
        if order_books has asset_pair:
            order_books[asset_pair].remove(descriptor)
            "Clean up empty order books"
            if order_books[asset_pair] is empty:
                order_books.remove(asset_pair)
```

### update_offer

```
update_offer(offer):
    "handles case where offer's price or assets might change"
    remove_offer(offer.seller_id, offer.offer_id)
    add_offer(offer)
```

### best_offer_key

```
best_offer_key(buying, selling):
    asset_pair = AssetPair(buying, selling)
    → first entry in order_books[asset_pair] (lowest price)
```

### best_offer_key_filtered

"Used during offer crossing to skip already-processed or same-account offers"

```
best_offer_key_filtered(buying, selling, filter_fn):
    asset_pair = AssetPair(buying, selling)
    for each (descriptor, key) in order_books[asset_pair]:
        if filter_fn(key) is true:
            → key
    → none
```

### offers_for_pair

```
offers_for_pair(buying, selling):
    asset_pair = AssetPair(buying, selling)
    → iterator over all OfferKeys in order_books[asset_pair] (price order)
```

### has_offers

```
has_offers(buying, selling):
    asset_pair = AssetPair(buying, selling)
    → order_books has asset_pair AND book is non-empty
```

### Utility functions

```
len():       → offer_locations.size
is_empty():  → offer_locations is empty
clear():     order_books.clear(); offer_locations.clear()
num_asset_pairs(): → order_books.size
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 237    | ~90        |
| Functions     | 13     | 13         |
