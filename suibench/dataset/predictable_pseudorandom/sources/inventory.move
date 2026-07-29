/// Equipments of hero
module challenge::inventory {
    use challenge::random;

    /// Upper bound on how magical a sword can be
    const MAX_RARITY: u64 = 5;
    const BASE_SWORD_STRENGTH: u64 = 2;
    const BASE_ARMOR_DEFENSE: u64 = 1;

    /// The hero's trusty sword
    public struct Sword has store {
        /// Constant set at creation. Acts as a multiplier on sword's strength.
        /// Swords with high rarity are rarer, rarity ranges between [1, 5]
        rarity: u64,
        /// Strength that will be add to hero once equipped.
        strength: u64,
    }

    /// Armor
    public struct Armor has store {
        /// Constant set at creation. Acts as a multiplier on armor's defense.
        /// Armors with high rarity are rarer, rarity ranges between [1, 5]
        rarity: u64,
        /// Defense that will be add to hero once euipped.
        defense: u64,
    }

    public struct TreasuryBox has key, store {
        id: UID,
    }

    public(package) fun create_treasury_box(ctx: &mut TxContext): TreasuryBox {
        TreasuryBox {
            id: object::new(ctx)
        }
    }

    /// Create a new sword, the rarity value is random generated.
    public(package) fun create_sword(_ctx: &mut TxContext): Sword {
        Sword {
            rarity: 1,
            strength: BASE_SWORD_STRENGTH,
        }
    }

    public fun destroy_sword(sword: Sword) {
        let Sword { rarity: _, strength: _} = sword;
    }

    /// Create a new armor, the rarity value is random generated.
    public(package) fun create_armor(_ctx: &mut TxContext): Armor {
        Armor {
            rarity: 1,
            defense: BASE_ARMOR_DEFENSE,
        }
    }

    public fun destroy_armor(armor: Armor) {
        let Armor { rarity: _, defense: _} = armor;
    }

    /// Get the strength of a sword: rarity * strength
    public fun strength(sword: &Sword): u64 {
        sword.strength * sword.rarity
    }

    /// Get the defense of an armor: rarity * defense
    public fun defense(armor: &Armor): u64 {
        armor.defense * armor.rarity
    }

    public fun sword_rarity(sword: &Sword): u64 {
        sword.rarity
    }

    public fun armor_rarity(armor: &Armor): u64 {
        armor.rarity
    }

    /// Level up a sword with another one.
    /// The probability of success is: 1 / sword.rarity.
    public fun level_up_sword(sword: &mut Sword, material: Sword, ctx: &mut TxContext) {
        if (sword.rarity < MAX_RARITY) {
            let prob = random::rand_u64_range(0, sword.rarity, ctx);
            if (prob < 1) {
                sword.rarity = sword.rarity + 1;
            }
        };
        destroy_sword(material);
    }

    /// Level up an armor with another one.
    /// The probability of success is: 1 / armor.rarity.
    public fun level_up_armor(armor: &mut Armor, material: Armor, ctx: &mut TxContext) {
        if (armor.rarity < MAX_RARITY) {
            let prob = random::rand_u64_range(0, armor.rarity, ctx);
            if (prob < 1) {
                armor.rarity = armor.rarity + 1;
            }
        };
        destroy_armor(material);
    }
}
