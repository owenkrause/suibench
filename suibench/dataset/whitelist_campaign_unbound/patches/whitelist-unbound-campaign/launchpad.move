module challenge::launchpad {
    use sui::vec_set::{Self, VecSet};
    use sui::table::{Self, Table};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;

    const ENotWhitelisted: u64 = 0;
    const EWrongCampaign: u64 = 1;

    public struct Campaign has key {
        id: UID,
        admin: address,
        raised: Balance<SUI>,
        allocations: Table<address, u64>,
    }

    public struct Whitelist has key {
        id: UID,
        campaign_id: ID,
        members: VecSet<address>,
    }

    public fun create_campaign(ctx: &mut TxContext) {
        transfer::share_object(Campaign {
            id: object::new(ctx),
            admin: ctx.sender(),
            raised: balance::zero(),
            allocations: table::new(ctx),
        });
    }

    public fun create_whitelist(campaign: &Campaign, ctx: &mut TxContext) {
        transfer::share_object(Whitelist {
            id: object::new(ctx),
            campaign_id: object::id(campaign),
            members: vec_set::empty(),
        });
    }

    public fun add_member(whitelist: &mut Whitelist, member: address) {
        vec_set::insert(&mut whitelist.members, member);
    }

    public fun invest(campaign: &mut Campaign, whitelist: &Whitelist, payment: Coin<SUI>, ctx: &TxContext) {
        assert!(whitelist.campaign_id == object::id(campaign), EWrongCampaign);
        let sender = ctx.sender();
        assert!(vec_set::contains(&whitelist.members, &sender), ENotWhitelisted);
        let amount = coin::value(&payment);
        balance::join(&mut campaign.raised, coin::into_balance(payment));
        if (table::contains(&campaign.allocations, sender)) {
            let a = table::borrow_mut(&mut campaign.allocations, sender);
            *a = *a + amount;
        } else {
            table::add(&mut campaign.allocations, sender, amount);
        }
    }
}
