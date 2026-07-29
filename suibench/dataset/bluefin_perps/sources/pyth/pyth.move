module pyth::pyth {

    use pyth::price_info::{Self, PriceInfo, PriceInfoObject};
    use pyth::price_feed::{Self};
    use pyth::price::{Self, Price};


    public entry fun create_price(): PriceInfo{
        let value = price_info::new_price_info(
                    1663680747,
                    1663074349,
                    price_feed::new(
                        pyth::price_identifier::from_byte_vec(x"c6c75c89f14810ec1c54c03ab8f1864a4c4032791f05747f560faec380a695d1"),
                        price::new(pyth::i64::new(1557, false), 7, pyth::i64::new(6, true), 1663680740),
                        price::new(pyth::i64::new(1500, false), 3, pyth::i64::new(6, true), 1663680740),
                    ) );
        return value
    }



    /// Returns the latest stored price for the given price info object.
    public entry fun get_price_unsafe(price_info_object: &PriceInfoObject): Price {
        let price_info = price_info::get_price_info_from_price_info_object(price_info_object);
        price_feed::get_price(
            price_info::get_price_feed(&price_info)
        )
    }
}
