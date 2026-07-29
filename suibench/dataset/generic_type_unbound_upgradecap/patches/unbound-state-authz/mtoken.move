module challenge::mtoken {
    use sui::package::UpgradeCap;

    const ENotOwner: u64 = 0;
    const EWrongState: u64 = 1;

    public struct State<phantom T> has key {
        id: UID,
        owner: address,
    }

    public struct TransferOwnershipReq has key, store {
        id: UID,
        state_id: ID,
        cap: UpgradeCap,
    }

    public fun create_state<T>(ctx: &mut TxContext) {
        transfer::share_object(State<T> {
            id: object::new(ctx),
            owner: ctx.sender(),
        });
    }

    fun check_owner<T>(state: &State<T>, ctx: &TxContext) {
        assert!(state.owner == ctx.sender(), ENotOwner);
    }

    public fun request_transfer_ownership<T>(state: &State<T>, cap: UpgradeCap, ctx: &mut TxContext): TransferOwnershipReq {
        check_owner(state, ctx);
        TransferOwnershipReq {
            id: object::new(ctx),
            state_id: object::id(state),
            cap,
        }
    }

    public fun revoke_transfer_ownership<T>(state: &State<T>, req: TransferOwnershipReq, ctx: &mut TxContext) {
        check_owner(state, ctx);
        assert!(object::id(state) == req.state_id, EWrongState);
        let TransferOwnershipReq { id, state_id: _, cap } = req;
        object::delete(id);
        transfer::public_transfer(cap, ctx.sender());
    }
}
