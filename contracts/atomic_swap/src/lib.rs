#![no_std]
use ip_registry::IpRegistryClient;
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

// ── Storage Keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Swap(u64),
    NextId,
    /// Maps ip_id → swap_id for any swap currently in Pending or Accepted state.
    /// Cleared when a swap reaches Completed or Cancelled.
    ActiveSwap(u64),
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, PartialEq, Eq)]
pub enum SwapStatus {
    Pending,
    Accepted,
    Completed,
    Cancelled,
}

#[contracttype]
#[derive(Clone)]
pub struct SwapRecord {
    pub ip_id: u64,
    pub seller: Address,
    pub buyer: Address,
    pub price: i128,
    pub status: SwapStatus,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AtomicSwap;

#[contractimpl]
impl AtomicSwap {
    /// Seller initiates a patent sale. Returns the swap ID.
    ///
    /// Security invariants enforced here:
    ///   1. `seller` must sign the transaction (`require_auth`).
    ///   2. `seller` must be the registered owner of `ip_id` in IpRegistry
    ///      (cross-contract call). Any other address is rejected.
    ///   3. No active (Pending / Accepted) swap may already exist for this IP.
    pub fn initiate_swap(
        env: Env,
        ip_registry_id: Address,
        ip_id: u64,
        seller: Address,
        price: i128,
        buyer: Address,
    ) -> u64 {
        // 1. Require the seller's authorisation.
        seller.require_auth();

        // 2. Cross-contract ownership check.
        let registry = IpRegistryClient::new(&env, &ip_registry_id);
        let record = registry.get_ip(&ip_id);
        assert!(record.owner == seller, "seller is not the IP owner");

        // 3. Guard: reject if an active swap already exists for this IP.
        assert!(
            !env.storage().persistent().has(&DataKey::ActiveSwap(ip_id)),
            "active swap already exists for this ip_id"
        );

        let id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextId)
            .unwrap_or(0);

        let swap = SwapRecord {
            ip_id,
            seller,
            buyer,
            price,
            status: SwapStatus::Pending,
        };

        env.storage().persistent().set(&DataKey::Swap(id), &swap);
        env.storage()
            .persistent()
            .set(&DataKey::ActiveSwap(ip_id), &id);
        env.storage()
            .instance()
            .set(&DataKey::NextId, &(id + 1));
        id
    }

    /// Buyer accepts the swap and sends payment (payment handled by token contract in full impl).
    pub fn accept_swap(env: Env, swap_id: u64) {
        let mut swap: SwapRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Swap(swap_id))
            .expect("swap not found");

        assert!(swap.status == SwapStatus::Pending, "swap not pending");
        swap.status = SwapStatus::Accepted;
        env.storage()
            .persistent()
            .set(&DataKey::Swap(swap_id), &swap);
    }

    /// Seller reveals the decryption key; payment releases.
    pub fn reveal_key(env: Env, swap_id: u64, _decryption_key: BytesN<32>) {
        let mut swap: SwapRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Swap(swap_id))
            .expect("swap not found");

        assert!(swap.status == SwapStatus::Accepted, "swap not accepted");
        // Full impl: verify key against IP commitment, then transfer escrowed payment.
        swap.status = SwapStatus::Completed;
        env.storage()
            .persistent()
            .set(&DataKey::Swap(swap_id), &swap);
        // Release the IP lock so a new swap can be created.
        env.storage()
            .persistent()
            .remove(&DataKey::ActiveSwap(swap.ip_id));
    }

    /// Cancel a swap (invalid key or timeout).
    pub fn cancel_swap(env: Env, swap_id: u64) {
        let mut swap: SwapRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Swap(swap_id))
            .expect("swap not found");

        assert!(
            swap.status == SwapStatus::Pending || swap.status == SwapStatus::Accepted,
            "swap already finalised"
        );
        swap.status = SwapStatus::Cancelled;
        env.storage()
            .persistent()
            .set(&DataKey::Swap(swap_id), &swap);
        // Release the IP lock so a new swap can be created.
        env.storage()
            .persistent()
            .remove(&DataKey::ActiveSwap(swap.ip_id));
    }

    /// Read a swap record. Returns `None` if the swap_id does not exist.
    pub fn get_swap(env: Env, swap_id: u64) -> Option<SwapRecord> {
        env.storage().persistent().get(&DataKey::Swap(swap_id))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ip_registry::{IpRegistry, IpRegistryClient};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{BytesN, Env};

    /// Registers an IpRegistry contract, commits an IP owned by `owner`,
    /// and returns `(registry_contract_id, ip_id)`.
    fn setup_registry_with_ip(env: &Env, owner: &Address) -> (Address, u64) {
        let registry_id = env.register(IpRegistry, ());
        let registry = IpRegistryClient::new(env, &registry_id);
        let commitment = BytesN::from_array(env, &[0u8; 32]);
        let ip_id = registry.commit_ip(owner, &commitment);
        (registry_id, ip_id)
    }

    fn setup_swap(env: &Env) -> Address {
        env.register(AtomicSwap, ())
    }

    #[test]
    fn get_swap_returns_none_for_nonexistent_id() {
        let env = Env::default();
        let client = AtomicSwapClient::new(&env, &setup_swap(&env));
        assert!(client.get_swap(&9999).is_none());
    }

    #[test]
    fn get_swap_returns_some_for_existing_swap() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let (registry_id, ip_id) = setup_registry_with_ip(&env, &seller);

        let client = AtomicSwapClient::new(&env, &setup_swap(&env));
        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &100_i128, &buyer);

        let swap = client.get_swap(&swap_id).unwrap();
        assert_eq!(swap.ip_id, ip_id);
        assert_eq!(swap.price, 100_i128);
        assert_eq!(swap.status, SwapStatus::Pending);
    }

    /// A second `initiate_swap` for the same `ip_id` must be rejected while the first is active.
    #[test]
    fn duplicate_swap_rejected_while_active() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let (registry_id, ip_id) = setup_registry_with_ip(&env, &seller);

        let client = AtomicSwapClient::new(&env, &setup_swap(&env));
        client.initiate_swap(&registry_id, &ip_id, &seller, &100_i128, &buyer);

        assert!(client
            .try_initiate_swap(&registry_id, &ip_id, &seller, &200_i128, &buyer)
            .is_err());
    }

    /// After a swap is cancelled the IP lock is released and a new swap can be created.
    #[test]
    fn new_swap_allowed_after_cancel() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let (registry_id, ip_id) = setup_registry_with_ip(&env, &seller);

        let client = AtomicSwapClient::new(&env, &setup_swap(&env));
        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &100_i128, &buyer);
        client.cancel_swap(&swap_id);

        let new_id = client.initiate_swap(&registry_id, &ip_id, &seller, &150_i128, &buyer);
        assert_ne!(new_id, swap_id);
    }

    /// After a swap completes the IP lock is released and a new swap can be created.
    #[test]
    fn new_swap_allowed_after_complete() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let (registry_id, ip_id) = setup_registry_with_ip(&env, &seller);

        let client = AtomicSwapClient::new(&env, &setup_swap(&env));
        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &100_i128, &buyer);
        client.accept_swap(&swap_id);
        client.reveal_key(&swap_id, &BytesN::from_array(&env, &[0u8; 32]));

        let new_id = client.initiate_swap(&registry_id, &ip_id, &seller, &150_i128, &buyer);
        assert_ne!(new_id, swap_id);
    }

    /// SECURITY: a non-owner must not be able to initiate a swap for an IP they do not own.
    #[test]
    fn non_owner_cannot_initiate_swap() {
        let env = Env::default();
        env.mock_all_auths();

        let real_owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        let buyer = Address::generate(&env);
        let (registry_id, ip_id) = setup_registry_with_ip(&env, &real_owner);

        let client = AtomicSwapClient::new(&env, &setup_swap(&env));

        assert!(
            client
                .try_initiate_swap(&registry_id, &ip_id, &attacker, &999_i128, &buyer)
                .is_err(),
            "expected initiate_swap to fail for non-owner"
        );
    }
}
