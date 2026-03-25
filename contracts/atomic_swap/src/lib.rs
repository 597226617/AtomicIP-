#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env};

// ── Storage Keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Swap(u64),
    NextId,
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, PartialEq)]
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

// ── Events ────────────────────────────────────────────────────────────────────

/// Payload published when a key is successfully revealed and the swap completes.
/// Topic: `key_revld` (symbol_short, max 9 chars) — used by off-chain indexers.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct KeyRevealedEvent {
    pub swap_id: u64,
    pub decryption_key: BytesN<32>,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AtomicSwap;

#[contractimpl]
impl AtomicSwap {
    /// Seller initiates a patent sale. Returns the swap ID.
    pub fn initiate_swap(env: Env, ip_id: u64, price: i128, buyer: Address) -> u64 {
        let seller = env.current_contract_address(); // placeholder; real impl uses invoker
        let id: u64 = env.storage().instance().get(&DataKey::NextId).unwrap_or(0);

        let swap = SwapRecord {
            ip_id,
            seller,
            buyer,
            price,
            status: SwapStatus::Pending,
        };

        env.storage().persistent().set(&DataKey::Swap(id), &swap);
        env.storage().instance().set(&DataKey::NextId, &(id + 1));
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
        env.storage().persistent().set(&DataKey::Swap(swap_id), &swap);
    }

    /// Seller reveals the decryption key; payment releases.
    /// Emits a `key_revld` event on success so external systems can detect
    /// when the key becomes available.
    pub fn reveal_key(env: Env, swap_id: u64, decryption_key: BytesN<32>) {
        let mut swap: SwapRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Swap(swap_id))
            .expect("swap not found");

        assert!(swap.status == SwapStatus::Accepted, "swap not accepted");
        // Full impl: verify key against IP commitment, then transfer escrowed payment
        swap.status = SwapStatus::Completed;
        env.storage().persistent().set(&DataKey::Swap(swap_id), &swap);

        // Emit event — only reached after successful state transition.
        env.events().publish(
            (symbol_short!("key_revld"),),
            KeyRevealedEvent { swap_id, decryption_key },
        );
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
        env.storage().persistent().set(&DataKey::Swap(swap_id), &swap);
    }

    /// Read a swap record.
    pub fn get_swap(env: Env, swap_id: u64) -> SwapRecord {
        env.storage()
            .persistent()
            .get(&DataKey::Swap(swap_id))
            .expect("swap not found")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, BytesN as _, Events},
        vec, Env, IntoVal,
    };

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AtomicSwap);
        (env, contract_id)
    }

    /// Bring a swap to Accepted state and return its ID + the key used.
    fn accepted_swap(env: &Env, client: &AtomicSwapClient) -> (u64, BytesN<32>) {
        let buyer = Address::generate(env);
        let swap_id = client.initiate_swap(&1u64, &1000_i128, &buyer);
        client.accept_swap(&swap_id);
        let key = BytesN::random(env);
        (swap_id, key)
    }

    #[test]
    fn test_reveal_key_emits_event_with_correct_values() {
        let (env, contract_id) = setup();
        let client = AtomicSwapClient::new(&env, &contract_id);
        let (swap_id, key) = accepted_swap(&env, &client);

        client.reveal_key(&swap_id, &key);

        // State must be Completed
        assert_eq!(client.get_swap(&swap_id).status, SwapStatus::Completed);

        // Exactly one event emitted
        let events = env.events().all();
        assert_eq!(events.len(), 1);

        // Topic is correct
        let (_, topics, data) = events.get(0).unwrap();
        assert_eq!(topics, vec![&env, symbol_short!("key_revld").into_val(&env)]);

        // Payload fields match exactly
        let payload: KeyRevealedEvent = data.into_val(&env);
        assert_eq!(payload.swap_id, swap_id);
        assert_eq!(payload.decryption_key, key);
    }

    #[test]
    #[should_panic(expected = "swap not accepted")]
    fn test_reveal_key_on_pending_swap_fails_no_event() {
        let (env, contract_id) = setup();
        let client = AtomicSwapClient::new(&env, &contract_id);
        let buyer = Address::generate(&env);
        let swap_id = client.initiate_swap(&1u64, &1000_i128, &buyer);
        let key = BytesN::random(&env);

        // Swap is still Pending — must panic before event fires
        client.reveal_key(&swap_id, &key);
    }

    #[test]
    #[should_panic(expected = "swap not accepted")]
    fn test_reveal_key_on_completed_swap_fails_no_event() {
        let (env, contract_id) = setup();
        let client = AtomicSwapClient::new(&env, &contract_id);
        let (swap_id, key) = accepted_swap(&env, &client);

        client.reveal_key(&swap_id, &key);
        // Second call on an already-Completed swap — must panic
        client.reveal_key(&swap_id, &key);
    }

    #[test]
    fn test_no_event_emitted_on_normal_completion_without_reveal() {
        let (env, contract_id) = setup();
        let client = AtomicSwapClient::new(&env, &contract_id);
        let buyer = Address::generate(&env);
        let swap_id = client.initiate_swap(&1u64, &1000_i128, &buyer);
        client.accept_swap(&swap_id);

        // No reveal_key called — events list must be empty
        assert_eq!(env.events().all().len(), 0);
    }
}
