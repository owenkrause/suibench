module challenge::launchpad {
    use sui::vec_set::{Self, VecSet};
    use sui::table::{Self, Table};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::event;
    use sui::sui::SUI;

    const ENotWhitelisted: u64 = 0;
    const EWrongCampaign: u64 = 1;
    const ENotWhitelistAdmin: u64 = 2;
    const ENotCampaignAdmin: u64 = 3;

    public struct Campaign has key { id: UID, admin: address, raised: Balance<SUI>, allocations: Table<address, u64> }
    public struct Whitelist has key { id: UID, admin: address, campaign_id: ID, members: VecSet<address> }
    public struct WhitelistCreated has copy, drop { actor: address, whitelist_id: ID, whitelist_admin: address, campaign_id: ID, campaign_admin: address }
    public struct WhitelistMemberAdded has copy, drop { actor: address, whitelist_id: ID, whitelist_admin: address, campaign_id: ID, member: address }
    public struct Investment has copy, drop { actor: address, whitelist_id: ID, campaign_id: ID, campaign_admin: address, whitelist_campaign_id: ID, amount: u64 }

    public fun create_campaign(ctx: &mut TxContext) {
        transfer::share_object(Campaign { id: object::new(ctx), admin: ctx.sender(), raised: balance::zero(), allocations: table::new(ctx) });
    }

    public fun create_whitelist(campaign: &Campaign, ctx: &mut TxContext) {
        let actor = ctx.sender();
        let campaign_id = object::id(campaign);
        let campaign_admin = campaign.admin;
        let whitelist = Whitelist { id: object::new(ctx), admin: actor, campaign_id, members: vec_set::empty() };
        let whitelist_id = object::id(&whitelist);
        transfer::share_object(whitelist);
        event::emit(WhitelistCreated { actor, whitelist_id, whitelist_admin: actor, campaign_id, campaign_admin });
    }

    public fun add_member(whitelist: &mut Whitelist, member: address, ctx: &TxContext) {
        assert!(ctx.sender() == whitelist.admin, ENotWhitelistAdmin);
        vec_set::insert(&mut whitelist.members, member);
        event::emit(WhitelistMemberAdded { actor: ctx.sender(), whitelist_id: object::id(whitelist), whitelist_admin: whitelist.admin, campaign_id: whitelist.campaign_id, member });
    }

    public fun invest(campaign: &mut Campaign, whitelist: &Whitelist, payment: Coin<SUI>, ctx: &TxContext) {
        let sender = ctx.sender();
        assert!(vec_set::contains(&whitelist.members, &sender), ENotWhitelisted);
        let campaign_id = object::id(campaign);
        let campaign_admin = campaign.admin;
        let whitelist_id = object::id(whitelist);
        let whitelist_campaign_id = whitelist.campaign_id;
        let amount = coin::value(&payment);
        balance::join(&mut campaign.raised, coin::into_balance(payment));
        if (table::contains(&campaign.allocations, sender)) { let a = table::borrow_mut(&mut campaign.allocations, sender); *a = *a + amount; } else { table::add(&mut campaign.allocations, sender, amount); };
        event::emit(Investment { actor: sender, whitelist_id, campaign_id, campaign_admin, whitelist_campaign_id, amount });
    }
}
