use hacash_wallet_core::fetch_spot_prices;

#[tokio::main]
async fn main() {
    match fetch_spot_prices().await {
        Ok(prices) => {
            println!("source={:?}", prices.source);
            println!("hac_usd={}", prices.hac_usd);
            println!("hacd_usd={}", prices.hacd_usd);
            println!("btc_usd={}", prices.btc_usd);
            println!("stale={}", prices.stale);
            println!("observed_at_utc={}", prices.observed_at_utc);
        }
        Err(error) => {
            eprintln!("price check failed: {error}");
            std::process::exit(1);
        }
    }
}
