module challenge::oracle;

use challenge::margin_registry::MarginRegistry;
use pyth::price_info::PriceInfoObject;
use sui::clock::Clock;

public(package) fun calculate_target_currency<FromAsset, ToAsset>(
    _registry: &MarginRegistry,
    _from_oracle: &PriceInfoObject,
    _to_oracle: &PriceInfoObject,
    amount: u64,
    _clock: &Clock,
): u64 {
    amount
}
