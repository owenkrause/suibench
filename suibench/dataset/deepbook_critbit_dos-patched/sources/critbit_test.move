// SCAFFOLDING. A minimal driver that wraps a
// CritbitTree<u64> in a shared object and exposes insert / remove / traversal
// entries so a transaction can drive the tree.
module challenge::critbit_test {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;
    use challenge::critbit::{Self, CritbitTree};

    // CritbitTree has `store` but not `key`, so it cannot be shared directly;
    // wrap it in a `key` holder.
    struct TreeHolder has key {
        id: UID,
        tree: CritbitTree<u64>,
    }

    fun init(ctx: &mut TxContext) {
        let tree = critbit::new<u64>(ctx);
        let holder = TreeHolder { id: object::new(ctx), tree };
        transfer::share_object(holder);
    }

    /// Insert a leaf with key = value = `key`.
    public entry fun insert(holder: &mut TreeHolder, key: u64) {
        critbit::insert_leaf(&mut holder.tree, key, key);
    }

    /// Remove a leaf by its leaf-table index (insertion order, 0-based).
    public entry fun remove_by_index(holder: &mut TreeHolder, index: u64) {
        critbit::remove_leaf_by_index(&mut holder.tree, index);
    }

    /// Next-leaf traversal from an existing key — the order-book iterator step.
    public entry fun victim_next(holder: &TreeHolder, key: u64) {
        let (_, _) = critbit::next_leaf(&holder.tree, key);
    }

    #[test_only]
    public fun init_for_test(ctx: &mut TxContext) {
        init(ctx);
    }
}
