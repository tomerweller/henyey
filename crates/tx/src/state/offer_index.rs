use super::*;

/// Descriptor for an offer used in the order book index.
/// Offers are sorted by price (ascending) then offer ID (ascending).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferDescriptor {
    /// Price as n/d ratio.
    pub price: Price,
    /// Unique offer identifier.
    pub offer_id: i64,
}

impl OfferDescriptor {
    /// Create a new offer descriptor from an offer entry.
    pub fn from_offer(offer: &OfferEntry) -> Self {
        Self {
            price: offer.price.clone(),
            offer_id: offer.offer_id,
        }
    }
}

/// Comparator for offers: lower price is better, then lower offer ID.
impl Ord for OfferDescriptor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Use floating-point comparison to match stellar-core behavior.
        // The stellar-core code uses `double(price.n) / double(price.d)` for ordering.
        let self_price = self.price.n as f64 / self.price.d as f64;
        let other_price = other.price.n as f64 / other.price.d as f64;

        match self_price.partial_cmp(&other_price) {
            Some(std::cmp::Ordering::Equal) | None => self.offer_id.cmp(&other.offer_id),
            Some(ord) => ord,
        }
    }
}

impl PartialOrd for OfferDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Key for an offer in the primary offers map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OfferKey {
    /// Seller account ID (32 bytes).
    pub seller: [u8; 32],
    /// Offer ID.
    pub offer_id: i64,
}

impl OfferKey {
    /// Create a new offer key.
    pub fn new(seller: [u8; 32], offer_id: i64) -> Self {
        Self { seller, offer_id }
    }

    /// Create from an offer entry.
    pub fn from_offer(offer: &OfferEntry) -> Self {
        Self {
            seller: account_id_to_bytes(&offer.seller_id),
            offer_id: offer.offer_id,
        }
    }
}

/// Asset pair key for order book lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetPair {
    /// Asset being bought.
    pub buying: AssetKey,
    /// Asset being sold.
    pub selling: AssetKey,
}

impl AssetPair {
    /// Create a new asset pair from XDR assets.
    pub fn new(buying: &Asset, selling: &Asset) -> Self {
        Self {
            buying: AssetKey::from_asset(buying),
            selling: AssetKey::from_asset(selling),
        }
    }
}

/// Order book for a single asset pair.
/// Offers are stored in a BTreeMap sorted by (price, offer_id) for O(log n) best offer lookup.
type OrderBook = BTreeMap<OfferDescriptor, OfferKey>;

/// Index of all offers organized by asset pair for efficient best-offer queries.
///
/// This mirrors stellar-core's MultiOrderBook structure. Each asset pair
/// has its own order book (BTreeMap) where offers are sorted by price and offer ID.
///
/// # Performance
///
/// - `best_offer`: O(log n) where n is offers for the asset pair
/// - `add_offer`: O(log n)
/// - `remove_offer`: O(log n)
/// - `update_offer`: O(log n) for same asset pair, O(log n + log m) if assets change
#[derive(Debug, Clone, Default)]
pub struct OfferIndex {
    /// Order books keyed by (buying, selling) asset pair.
    order_books: HashMap<AssetPair, OrderBook>,
    /// Reverse index: offer key -> (asset pair, descriptor) for efficient removal.
    offer_locations: HashMap<OfferKey, (AssetPair, OfferDescriptor)>,
}

impl OfferIndex {
    /// Create a new empty offer index.
    pub fn new() -> Self {
        Self {
            order_books: HashMap::new(),
            offer_locations: HashMap::new(),
        }
    }

    /// Add an offer to the index.
    pub fn add_offer(&mut self, offer: &OfferEntry) {
        let key = OfferKey::from_offer(offer);
        let descriptor = OfferDescriptor::from_offer(offer);
        let asset_pair = AssetPair::new(&offer.buying, &offer.selling);

        // Add to order book
        let order_book = self.order_books.entry(asset_pair.clone()).or_default();
        order_book.insert(descriptor.clone(), key);

        // Add to reverse index
        self.offer_locations.insert(key, (asset_pair, descriptor));
    }

    /// Remove an offer from the index.
    pub fn remove_offer(&mut self, seller: &AccountId, offer_id: i64) {
        let key = OfferKey::new(account_id_to_bytes(seller), offer_id);
        self.remove_by_key(&key);
    }

    /// Remove an offer from the index by its key.
    pub fn remove_by_key(&mut self, key: &OfferKey) {
        // Look up location in reverse index
        if let Some((asset_pair, descriptor)) = self.offer_locations.remove(key) {
            // Remove from order book
            if let Some(order_book) = self.order_books.get_mut(&asset_pair) {
                order_book.remove(&descriptor);
                // Clean up empty order books
                if order_book.is_empty() {
                    self.order_books.remove(&asset_pair);
                }
            }
        }
    }

    /// Update an offer in the index.
    ///
    /// This handles the case where an offer's price or assets might change.
    pub fn update_offer(&mut self, offer: &OfferEntry) {
        // Remove old entry if exists
        self.remove_offer(&offer.seller_id, offer.offer_id);
        // Add with new values
        self.add_offer(offer);
    }

    /// Get the best (lowest price) offer for an asset pair.
    ///
    /// Returns the offer key if one exists.
    pub fn best_offer_key(&self, buying: &Asset, selling: &Asset) -> Option<OfferKey> {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books
            .get(&asset_pair)
            .and_then(|book| book.first_key_value())
            .map(|(_, key)| *key)
    }

    /// Get the best offer for an asset pair, excluding specific offers.
    ///
    /// This is used during offer crossing when we need to skip offers
    /// that have already been processed or belong to the same account.
    pub fn best_offer_key_filtered<F>(
        &self,
        buying: &Asset,
        selling: &Asset,
        mut filter: F,
    ) -> Option<OfferKey>
    where
        F: FnMut(&OfferKey) -> bool,
    {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books.get(&asset_pair).and_then(|book| {
            book.iter()
                .find(|(_, key)| filter(key))
                .map(|(_, key)| *key)
        })
    }

    /// Iterate over all offers for an asset pair in price order.
    pub fn offers_for_pair(
        &self,
        buying: &Asset,
        selling: &Asset,
    ) -> impl Iterator<Item = &OfferKey> {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books
            .get(&asset_pair)
            .into_iter()
            .flat_map(|book| book.values())
    }

    /// Check if the index contains any offers for an asset pair.
    pub fn has_offers(&self, buying: &Asset, selling: &Asset) -> bool {
        let asset_pair = AssetPair::new(buying, selling);
        self.order_books
            .get(&asset_pair)
            .is_some_and(|book| !book.is_empty())
    }

    /// Get the total number of offers in the index.
    pub fn len(&self) -> usize {
        self.offer_locations.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.offer_locations.is_empty()
    }

    /// Clear all offers from the index.
    pub fn clear(&mut self) {
        self.order_books.clear();
        self.offer_locations.clear();
    }

    /// Get the number of asset pairs with offers.
    pub fn num_asset_pairs(&self) -> usize {
        self.order_books.len()
    }
}
