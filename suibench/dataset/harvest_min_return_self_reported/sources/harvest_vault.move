module challenge::strategy_vault {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use challenge::asset::ASSET;

    const BPS_DENOM: u64 = 10_000;
    const MIN_RETURN_BPS: u64 = 9_800;

    const ENotOperator: u64 = 0;
    const ENotInOperation: u64 = 1;
    const EInsufficientReturn: u64 = 2;

    public struct Vault has key {
        id: UID,
        operator: address,
        funds: Balance<ASSET>,
        operation_in_progress: bool,
        principal: u64,
    }

    public struct HarvestOp {}

    public fun create_vault(operator: address, ctx: &mut TxContext) {
        transfer::share_object(Vault { id: object::new(ctx), operator, funds: balance::zero(), operation_in_progress: false, principal: 0 });
    }

    public fun deposit(vault: &mut Vault, coin: Coin<ASSET>) {
        vault.principal = vault.principal + coin::value(&coin);
        balance::join(&mut vault.funds, coin::into_balance(coin));
    }

    public fun start_harvest(vault: &mut Vault, ctx: &TxContext): HarvestOp {
        assert!(ctx.sender() == vault.operator, ENotOperator);
        vault.operation_in_progress = true;
        HarvestOp {}
    }

    public fun withdraw_for_strategy(vault: &mut Vault, _op: &mut HarvestOp, amount: u64, ctx: &mut TxContext): Coin<ASSET> {
        assert!(ctx.sender() == vault.operator, ENotOperator);
        assert!(vault.operation_in_progress, ENotInOperation);
        coin::from_balance(balance::split(&mut vault.funds, amount), ctx)
    }

    public fun finish_harvest(vault: &mut Vault, op: HarvestOp, returned_amount: u64, ctx: &TxContext) {
        assert!(ctx.sender() == vault.operator, ENotOperator);
        assert!(vault.operation_in_progress, ENotInOperation);
        let required = vault.principal * MIN_RETURN_BPS / BPS_DENOM;
        assert!(returned_amount >= required, EInsufficientReturn);
        vault.operation_in_progress = false;
        let HarvestOp {} = op;
    }
}
