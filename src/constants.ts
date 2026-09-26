/** Protocol constants from the Kyron specification. All supplies are in base units. */

export const NAME = "Kyron";
export const TICKER = "KRN";
export const CATEGORY = "Privacy-focused Layer 1";
export const CONSENSUS = "Proof-of-Stake";
export const DECIMALS = 18;
export const BASE_UNIT = 10n ** BigInt(DECIMALS);

export const MAX_SUPPLY_KRN = 455_000_000n;
export const INITIAL_SUPPLY_KRN = 127_400_000n;
export const UNRELEASED_SUPPLY_KRN = 327_600_000n;
export const TRANCHE_KRN = 81_900_000n;

export const MAX_SUPPLY = MAX_SUPPLY_KRN * BASE_UNIT;
export const INITIAL_SUPPLY = INITIAL_SUPPLY_KRN * BASE_UNIT;
export const UNRELEASED_SUPPLY = UNRELEASED_SUPPLY_KRN * BASE_UNIT;
export const TRANCHE_AMOUNT = TRANCHE_KRN * BASE_UNIT;

/** Four equal 18% tranches every 24 months after launch. */
export const TRANCHE_COUNT = 4;
export const TRANCHE_PERCENT_BPS = 1800; // 18.00%
export const RELEASE_INTERVAL_MS = 24 * 30 * 24 * 60 * 60 * 1000; // 24 months of 30-day months
export const RELEASE_INTERVAL_SLOTS = 24n * 30n * 24n * 60n * 60n; // 1 slot = 1 second

export const SLOT_DURATION_MS = 1000;
export const SLOTS_PER_EPOCH = 32;
export const MIN_VALIDATOR_STAKE = 10_000n * BASE_UNIT;
export const MAX_VALIDATORS = 256;
export const FINALITY_THRESHOLD_BPS = 6667; // 2/3 + epsilon in basis points of live stake
export const SLASH_DOUBLE_SIGN_BPS = 5000; // 50%
export const SLASH_DOWNTIME_BPS = 100; // 1%
export const DOWNTIME_WINDOW_SLOTS = 256;
export const DOWNTIME_MISS_THRESHOLD = 128;

export const BASE_FEE = 10n ** 14n; // 0.0001 KRN
export const FEE_PER_BYTE = 10n ** 11n;
export const SHIELDED_FEE_MULTIPLIER = 4n;

export const ADDRESS_HRP = "krn";
export const TREASURY_ADDRESS = "krn1treasury00000000000000000000000000000000";
export const RESERVE_ADDRESS = "krn1reserve000000000000000000000000000000000";
export const FEE_POOL_ADDRESS = "krn1feepool00000000000000000000000000000000";

export const PROTOCOL_VERSION = 1;
export const CHAIN_ID = "kyron-mainnet-ref-1";

export const MERKLE_DEPTH = 32;
export const EMPTY_HASH = new Uint8Array(32);
