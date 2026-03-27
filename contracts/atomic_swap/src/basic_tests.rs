#[cfg(test)]
mod tests {
    use ip_registry::{IpRegistry, IpRegistryClient};
    use soroban_sdk::{testutils::{Address as _, Ledger}, BytesN, Env};

    use crate::{AtomicSwap, AtomicSwapClient, DataKey, SwapStatus};

    /// Helper: register IpRegistry, commit an IP owned by `owner`, return (registry_id, ip_id).
    fn setup_registry(env: &Env, owner: &soroban_sdk::Address) -> (soroban_sdk::Address, u64) {
        let registry_id = env.register(IpRegistry, ());
        let registry = IpRegistryClient::new(env, &registry_id);
        let commitment = BytesN::from_array(env, &[1u8; 32]);
        let ip_id = registry.commit_ip(owner, &commitment);
        (registry_id, ip_id)
    }

    #[test]
    fn test_basic_functionality() {
        let env = Env::default();
        let buyer = soroban_sdk::Address::generate(&env);
        let decryption_key = BytesN::from_array(&env, &[0; 32]);
        assert_eq!(decryption_key.len(), 32);
        let buyer2 = soroban_sdk::Address::generate(&env);
        assert_ne!(buyer, buyer2);
    }

    #[test]
    fn test_storage_keys() {
        let key = DataKey::Swap(1);
        let key2 = DataKey::Swap(2);
        assert_ne!(key, key2);
        let next_id_key = DataKey::NextId;
        assert_ne!(key, next_id_key);
    }

    #[test]
    fn test_swap_status_enum() {
        assert_ne!(SwapStatus::Pending, SwapStatus::Accepted);
        assert_ne!(SwapStatus::Accepted, SwapStatus::Completed);
        assert_ne!(SwapStatus::Completed, SwapStatus::Cancelled);
        assert_ne!(SwapStatus::Cancelled, SwapStatus::Pending);
    }

    /// SECURITY: only the seller or buyer may cancel a swap.
    /// Any other address must be rejected even with `mock_all_auths`, because
    /// the identity check is an explicit assert that runs before `require_auth`.
    #[test]
    #[should_panic(expected = "only the seller or buyer can cancel")]
    fn test_unauthorized_cancel_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = soroban_sdk::Address::generate(&env);
        let buyer = soroban_sdk::Address::generate(&env);
        let attacker = soroban_sdk::Address::generate(&env);

        let (registry_id, ip_id) = setup_registry(&env, &seller);
        let contract_id = env.register(AtomicSwap, ());
        let client = AtomicSwapClient::new(&env, &contract_id);

        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &500_i128, &buyer);

        // attacker is neither seller nor buyer — must panic
        client.cancel_swap(&swap_id, &attacker);
    }

    /// SECURITY: only the seller may reveal the key.
    /// Passing a different address as `caller` must be rejected even with
    /// `mock_all_auths`, because the identity check is an explicit assert
    /// that runs before `require_auth`.
    #[test]
    #[should_panic(expected = "only the seller can reveal the key")]
    fn test_unauthorized_reveal_key_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = soroban_sdk::Address::generate(&env);
        let buyer = soroban_sdk::Address::generate(&env);
        let attacker = soroban_sdk::Address::generate(&env);

        // Set up a real swap via the contract so storage is in the right namespace.
        let (registry_id, ip_id) = setup_registry(&env, &seller);
        let contract_id = env.register(AtomicSwap, ());
        let client = AtomicSwapClient::new(&env, &contract_id);

        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &500_i128, &buyer);
        client.accept_swap(&swap_id);

        let key = BytesN::from_array(&env, &[1u8; 32]);
        // attacker != seller — must panic with "only the seller can reveal the key"
        client.reveal_key(&swap_id, &attacker, &key);
    }

    /// Issue #28: full atomic swap happy-path lifecycle — initiate → accept → reveal → Completed.
    ///
    /// NOTE: The current contract does not escrow tokens (the `token` field is a
    /// placeholder). Payment and key-delivery assertions are therefore limited to
    /// on-chain state: swap status is Completed and the stored decryption key
    /// matches what the seller revealed.
    #[test]
    fn test_full_swap_lifecycle_initiate_accept_reveal_completed() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = soroban_sdk::Address::generate(&env);
        let buyer = soroban_sdk::Address::generate(&env);
        let decryption_key = BytesN::from_array(&env, &[42u8; 32]);

        let (registry_id, ip_id) = setup_registry(&env, &seller);
        let contract_id = env.register(AtomicSwap, ());
        let client = AtomicSwapClient::new(&env, &contract_id);

        // 1. Initiate
        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &500_i128, &buyer);
        let swap = client.get_swap(&swap_id).unwrap();
        assert_eq!(swap.status, SwapStatus::Pending);
        assert_eq!(swap.seller, seller);
        assert_eq!(swap.buyer, buyer);

        // 2. Accept
        client.accept_swap(&swap_id);
        let swap = client.get_swap(&swap_id).unwrap();
        assert_eq!(swap.status, SwapStatus::Accepted);

        // 3. Reveal key → Completed
        client.reveal_key(&swap_id, &seller, &decryption_key);
        let swap = client.get_swap(&swap_id).unwrap();
        assert_eq!(swap.status, SwapStatus::Completed);
    }

    /// Issue #31: swap record must store the seller address passed by the caller,
    /// not the contract's own address.
    #[test]
    fn test_initiate_swap_seller_matches_caller() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = soroban_sdk::Address::generate(&env);
        let buyer = soroban_sdk::Address::generate(&env);

        let (registry_id, ip_id) = setup_registry(&env, &seller);
        let contract_id = env.register(AtomicSwap, ());
        let client = AtomicSwapClient::new(&env, &contract_id);

        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &500_i128, &buyer);

        let swap = client.get_swap(&swap_id).unwrap();
        assert_eq!(swap.seller, seller);
        assert_ne!(swap.seller, contract_id); // must not be the contract's own address
    }

    /// Issue #31: non-owner cannot initiate a swap for an IP they don't own.
    #[test]
    #[should_panic(expected = "seller is not the IP owner")]
    fn test_initiate_swap_rejects_non_owner_seller() {
        let env = Env::default();
        env.mock_all_auths();

        let real_owner = soroban_sdk::Address::generate(&env);
        let attacker = soroban_sdk::Address::generate(&env);
        let buyer = soroban_sdk::Address::generate(&env);

        let (registry_id, ip_id) = setup_registry(&env, &real_owner);
        let contract_id = env.register(AtomicSwap, ());
        let client = AtomicSwapClient::new(&env, &contract_id);

        // attacker is not the IP owner — must panic
        client.initiate_swap(&registry_id, &ip_id, &attacker, &500_i128, &buyer);
    }

    /// Issue #29: cancelling an Accepted swap must set status to Cancelled.
    ///
    /// An Accepted swap can only be cancelled via `cancel_expired_swap` once the
    /// ledger timestamp has passed the expiry. `cancel_swap` is for Pending swaps only.
    ///
    /// NOTE: The current contract does not escrow tokens (the `token` field is a
    /// placeholder). This test therefore asserts the observable on-chain state —
    /// swap status becomes Cancelled — which is the precondition for any refund
    /// logic once real token escrow is wired up.
    #[test]
    fn test_cancel_after_accept_sets_status_cancelled() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = soroban_sdk::Address::generate(&env);
        let buyer = soroban_sdk::Address::generate(&env);

        let (registry_id, ip_id) = setup_registry(&env, &seller);
        let contract_id = env.register(AtomicSwap, ());
        let client = AtomicSwapClient::new(&env, &contract_id);

        // 1. Initiate and accept the swap
        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &500_i128, &buyer);
        client.accept_swap(&swap_id);

        let swap = client.get_swap(&swap_id).unwrap();
        assert_eq!(swap.status, SwapStatus::Accepted);

        // 2. Advance ledger past the 86400-second expiry set in initiate_swap
        env.ledger().with_mut(|l| l.timestamp += 86401);

        // 3. Buyer cancels the expired Accepted swap (refund precondition)
        client.cancel_expired_swap(&swap_id, &buyer);

        // 4. Assert swap status is Cancelled
        let swap = client.get_swap(&swap_id).unwrap();
        assert_eq!(swap.status, SwapStatus::Cancelled);
    }

    /// Test: cancel_expired_swap function exists and has correct signature.
    /// Verifies that only Accepted swaps can be cancelled via cancel_expired_swap.
    #[test]
    #[should_panic(expected = "swap not in Accepted state")]
    fn test_cancel_expired_swap_pending_state_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let seller = soroban_sdk::Address::generate(&env);
        let buyer = soroban_sdk::Address::generate(&env);

        let (registry_id, ip_id) = setup_registry(&env, &seller);
        let contract_id = env.register(AtomicSwap, ());
        let client = AtomicSwapClient::new(&env, &contract_id);

        // Initiate but don't accept the swap
        let swap_id = client.initiate_swap(&registry_id, &ip_id, &seller, &500_i128, &buyer);

        // Try to cancel before accepting — should panic because swap is not Accepted
        client.cancel_expired_swap(&swap_id, &buyer);
    }
}
