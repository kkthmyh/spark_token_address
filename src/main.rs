use bech32::{self, ToBase32, Variant};
use hex;
use rand::{Rng as _, distr::Alphanumeric};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

const NETWORK_MAGIC_MAINNET: u32 = 3652501241;
const SPARK_TOKEN_CREATION_ENTITY_PUBLIC_KEY: &str =
    "0205fe807e8fe1f368df955cc291f16d840b7f28374b0ed80b80c3e2e0921a0674";
const NETWORK_PREFIX_MAINNET: &str = "btkn";

/// sha256
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// u128 -> 16字节数组
fn bigint_to_16_byte_array(mut value: u128) -> [u8; 16] {
    let mut buf = [0u8; 16];
    for i in (0..16).rev() {
        buf[i] = (value & 0xff) as u8;
        value >>= 8;
    }
    buf
}

/// hex -> Vec<u8>
fn get_uint8array_from_hex(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("invalid hex string")
}

/// 静态 hash
struct StaticTokenHashes {
    version_hash: [u8; 32],
    issuer_public_key_hash: [u8; 32],
    name_hash: [u8; 32],
    decimals_hash: [u8; 32],
    is_freezable_hash: [u8; 32],
    network_hash: [u8; 32],
    creation_entity_public_key_hash: [u8; 32],
}

/// 生成静态hash
fn precompute_static_hashes(
    issuer_public_key: &[u8],
    name: &str,
    decimals: u8,
    is_freezable: bool,
    network_magic: u32,
    creation_entity_public_key: &[u8],
) -> StaticTokenHashes {
    let one_hash = sha256(&[1]);
    let version_hash = one_hash;
    let name_hash = sha256(name.as_bytes());
    let decimals_hash = sha256(&[decimals]);
    let is_freezable_hash = sha256(&[is_freezable as u8]);

    let mut network_bytes = [0u8; 4];
    network_bytes.copy_from_slice(&network_magic.to_be_bytes());
    let network_hash = sha256(&network_bytes);

    let creation_entity_public_key_hash = if creation_entity_public_key.iter().all(|&b| b == 0) {
        one_hash
    } else {
        let mut layer_data = [0u8; 1 + 33];
        layer_data[0] = 2;
        layer_data[1..].copy_from_slice(&creation_entity_public_key[..33]);
        sha256(&layer_data)
    };

    let issuer_public_key_hash = sha256(issuer_public_key);

    StaticTokenHashes {
        version_hash,
        issuer_public_key_hash,
        name_hash,
        decimals_hash,
        is_freezable_hash,
        network_hash,
        creation_entity_public_key_hash,
    }
}

/// 拼接 hash
fn append_hash(buf: &mut [u8], offset: &mut usize, h: &[u8; 32]) {
    buf[*offset..*offset + 32].copy_from_slice(h);
    *offset += 32;
}

/// 根据tick和max_supply生成完整hash
fn get_token_identifier_with_dynamic(
    static_hashes: &StaticTokenHashes,
    ticker: &str,
    max_supply: u128,
) -> [u8; 32] {
    let ticker_hash = sha256(ticker.as_bytes());
    let max_supply_hash = sha256(&bigint_to_16_byte_array(max_supply));

    let mut buf = [0u8; 32 * 9]; // 9个hash
    let mut offset = 0;

    append_hash(&mut buf, &mut offset, &static_hashes.version_hash);
    append_hash(&mut buf, &mut offset, &static_hashes.issuer_public_key_hash);
    append_hash(&mut buf, &mut offset, &static_hashes.name_hash);
    append_hash(&mut buf, &mut offset, &ticker_hash);
    append_hash(&mut buf, &mut offset, &static_hashes.decimals_hash);
    append_hash(&mut buf, &mut offset, &max_supply_hash);
    append_hash(&mut buf, &mut offset, &static_hashes.is_freezable_hash);
    append_hash(&mut buf, &mut offset, &static_hashes.network_hash);
    append_hash(
        &mut buf,
        &mut offset,
        &static_hashes.creation_entity_public_key_hash,
    );

    sha256(&buf)
}

/// Bech32编码
fn encode_spark_human_readable_token_identifier(
    token_identifier: &[u8],
    network_prefix: &str,
) -> String {
    let words = token_identifier.to_base32();
    bech32::encode(network_prefix, words, Variant::Bech32m).expect("bech32m encode failed")
}

fn main() {
    let issuer_public_key = get_uint8array_from_hex("");
    let creation_entity_public_key =
        get_uint8array_from_hex(SPARK_TOKEN_CREATION_ENTITY_PUBLIC_KEY);
    let target_suffix = "fspks";

    let start = Instant::now();
    let found = Arc::new(AtomicBool::new(false));
    let hash_counter = Arc::new(AtomicU64::new(0));

    // 预计算静态部分
    let static_hashes = precompute_static_hashes(
        &issuer_public_key,
        target_suffix,
        8,
        false,
        NETWORK_MAGIC_MAINNET,
        &creation_entity_public_key,
    );
    let static_hashes = Arc::new(static_hashes);

    // 启动统计线程（每10秒打印一次速率）
    {
        let hash_counter = hash_counter.clone();
        let found = found.clone();
        thread::spawn(move || {
            let mut last_count = 0u64;
            while !found.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(10));
                let current = hash_counter.load(Ordering::Relaxed);
                let diff = current - last_count;
                last_count = current;
                println!("⚡ Speed: {:.2} hash/s", diff as f64 / 10.0);
            }
        });
    }

    // 并行搜索
    let max_js_safe: u128 = (1u128 << 53) - 1;
    let min_supply: u128 = 100_000_000;
    let num_threads = num_cpus::get();
    let step = (max_js_safe - min_supply + 1) / num_threads as u128;

    (0..num_threads).into_par_iter().for_each(|i| {
        let thread_start = min_supply + step * i as u128;
        let thread_end = if i == num_threads - 1 {
            max_js_safe
        } else {
            thread_start + step - 1
        };

        let static_hashes = static_hashes.clone();
        let found = found.clone();
        let hash_counter = hash_counter.clone();
        let mut rng = rand::rng();

        for max_supply in thread_start..=thread_end {
            if found.load(Ordering::Relaxed) {
                break;
            }

            let ticker: String = (0..6)
                .map(|_| rng.sample(Alphanumeric) as char)
                .collect::<String>()
                .to_uppercase();

            let token_id = get_token_identifier_with_dynamic(&static_hashes, &ticker, max_supply);
            hash_counter.fetch_add(1, Ordering::Relaxed);

            let human_readable =
                encode_spark_human_readable_token_identifier(&token_id, NETWORK_PREFIX_MAINNET);

            if human_readable.ends_with(target_suffix) {
                if !found.swap(true, Ordering::Relaxed) {
                    let elapsed = start.elapsed().as_secs_f64();
                    println!("✅ Found token address: {}", human_readable);
                    println!("max_supply: {}", max_supply);
                    println!("ticker: {}", ticker);
                    println!("⏱️ Time elapsed: {:.2} seconds", elapsed);
                }
                break;
            }
        }
    });
}
