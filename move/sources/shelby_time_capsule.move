/// Shelby Time Capsule — on-chain time enforcement
///
/// The contract stores a `time_key` (random key fragment) for each capsule.
/// This fragment is ONLY returned to callers after `unlock_time` has passed,
/// as verified by the Aptos blockchain's trusted clock.
///
/// Security model:
/// - time_key is locked in the contract until unlock_time (chain-enforced)
/// - Without time_key, the AES-256 ciphertext cannot be decrypted
/// - For recipient-bound capsules, the message is additionally encrypted to
///   the recipient's registered public key (see PubkeyRegistry below), so
///   only the holder of the matching private key can ever decrypt it —
///   independent of when they registered that key.
module shelby_capsule::time_capsule {
    use aptos_framework::timestamp;
    use std::signer;
    use aptos_framework::event;
    use aptos_std::table::{Self, Table};

    // ── Error codes ──────────────────────────────────────────────────────────
    const E_NOT_YET_TIME:      u64 = 1;
    const E_CAPSULE_NOT_FOUND: u64 = 2;
    const E_ALREADY_INIT:      u64 = 3;
    const E_UNLOCK_IN_PAST:    u64 = 4;
    const E_STORE_NOT_FOUND:   u64 = 5;
    const E_PUBKEY_NOT_FOUND:  u64 = 6;

    // ── Structs ──────────────────────────────────────────────────────────────

    /// A single sealed time capsule stored on-chain.
    struct Capsule has store, drop, copy {
        /// Random key fragment. Combined with the recipient's registered
        /// public key (if set) to form the AES-256 decryption key material.
        /// Only released after unlock_time.
        time_key: vector<u8>,

        /// Unix timestamp (seconds) after which time_key is released.
        unlock_time: u64,

        /// The wallet that sealed the capsule.
        author: address,

        /// Intended recipient. @0x0 means anyone can decrypt once unlocked.
        recipient: address,

        /// ShelbyNet blob ID (hex string) where the encrypted message lives.
        blob_id: vector<u8>,

        /// Blob name / path on ShelbyNet (e.g. "capsule/abc123.bin")
        blob_name: vector<u8>,

        /// When the capsule was created (seconds).
        created_at: u64,

        /// Whether the capsule is recipient-bound (true = needs recipient's
        /// registered public key to fully decrypt).
        recipient_bound: bool,
    }

    /// Global capsule registry stored under the deployer's address.
    struct CapsuleStore has key {
        capsules: Table<u64, Capsule>,
        capsule_count: u64,
    }

    /// Public-key registry: lets any wallet publish an encryption public key
    /// ahead of time, so senders can look it up and encrypt to it without
    /// the recipient needing to be present. Recipients can overwrite their
    /// own entry any time (e.g. to rotate keys); each address controls only
    /// its own slot.
    struct PubkeyRegistry has key {
        pubkeys: Table<address, vector<u8>>,
    }

    // ── Events ───────────────────────────────────────────────────────────────

    #[event]
    struct CapsuleSealed has drop, store {
        capsule_id: u64,
        author: address,
        recipient: address,
        unlock_time: u64,
        blob_id: vector<u8>,
    }

    #[event]
    struct CapsuleOpened has drop, store {
        capsule_id: u64,
        opener: address,
        opened_at: u64,
    }

    #[event]
    struct PubkeyRegistered has drop, store {
        owner: address,
    }

    // ── Initialization ───────────────────────────────────────────────────────

    /// Called automatically when the module is published.
    fun init_module(deployer: &signer) {
        move_to(deployer, CapsuleStore {
            capsules: table::new(),
            capsule_count: 0,
        });
        move_to(deployer, PubkeyRegistry {
            pubkeys: table::new(),
        });
    }

    // ── Entry functions ──────────────────────────────────────────────────────

    /// Seal a time capsule on-chain.
    ///
    /// @param time_key       — Random key fragment (32 bytes). Combined with
    ///                         the recipient's registered public key to form
    ///                         the final AES-256 key material.
    /// @param unlock_time    — Unix timestamp (seconds) after which the
    ///                         time_key will be released.
    /// @param recipient      — @0x0 for public, or a specific wallet address.
    /// @param blob_id        — ShelbyNet blob ID (hex bytes).
    /// @param blob_name      — ShelbyNet blob name (UTF-8 bytes).
    /// @param recipient_bound — true if the decryption key also depends on
    ///                          the recipient's registered public key.
    /// @param registry_addr  — Address where CapsuleStore lives (deployer).
    public entry fun seal_capsule(
        author: &signer,
        time_key: vector<u8>,
        unlock_time: u64,
        recipient: address,
        blob_id: vector<u8>,
        blob_name: vector<u8>,
        recipient_bound: bool,
        registry_addr: address,
    ) acquires CapsuleStore {
        let now = timestamp::now_seconds();
        assert!(unlock_time > now, E_UNLOCK_IN_PAST);
        assert!(exists<CapsuleStore>(registry_addr), E_STORE_NOT_FOUND);

        let store = borrow_global_mut<CapsuleStore>(registry_addr);
        let id = store.capsule_count;

        table::add(&mut store.capsules, id, Capsule {
            time_key,
            unlock_time,
            author: signer::address_of(author),
            recipient,
            blob_id: blob_id,
            blob_name: blob_name,
            created_at: now,
            recipient_bound,
        });

        store.capsule_count = id + 1;

        event::emit(CapsuleSealed {
            capsule_id: id,
            author: signer::address_of(author),
            recipient,
            unlock_time,
            blob_id: table::borrow(&store.capsules, id).blob_id,
        });
    }

    /// Register (or overwrite) the caller's own encryption public key.
    /// Anyone can call this at any time, independent of any capsule —
    /// this is the "one-time setup" step that lets others seal capsules
    /// to this wallet later without the wallet needing to be present.
    ///
    /// @param pubkey        — 32-byte X25519 public key, deterministically
    ///                        derived client-side from a wallet signature.
    /// @param registry_addr — Address where PubkeyRegistry lives (deployer).
    public entry fun register_pubkey(
        user: &signer,
        pubkey: vector<u8>,
        registry_addr: address,
    ) acquires PubkeyRegistry {
        assert!(exists<PubkeyRegistry>(registry_addr), E_STORE_NOT_FOUND);
        let reg = borrow_global_mut<PubkeyRegistry>(registry_addr);
        let owner = signer::address_of(user);

        if (table::contains(&reg.pubkeys, owner)) {
            table::upsert(&mut reg.pubkeys, owner, pubkey);
        } else {
            table::add(&mut reg.pubkeys, owner, pubkey);
        };

        event::emit(PubkeyRegistered { owner });
    }

    // ── View functions ────────────────────────────────────────────────────────

    /// Return the time_key for a capsule — ONLY if unlock_time has passed.
    /// This is the core on-chain time enforcement: the Aptos clock must
    /// confirm the moment has arrived before revealing the key.
    ///
    /// @returns time_key bytes if unlocked, aborts with E_NOT_YET_TIME otherwise.
    #[view]
    public fun get_time_key(
        registry_addr: address,
        capsule_id: u64,
    ): vector<u8> acquires CapsuleStore {
        assert!(exists<CapsuleStore>(registry_addr), E_STORE_NOT_FOUND);
        let store = borrow_global<CapsuleStore>(registry_addr);
        assert!(table::contains(&store.capsules, capsule_id), E_CAPSULE_NOT_FOUND);

        let capsule = table::borrow(&store.capsules, capsule_id);
        let now = timestamp::now_seconds();

        // ── THE CORE ENFORCEMENT ──────────────────────────────────────────
        // If this assertion fails, the call reverts on-chain.
        // No time_key is ever returned until the Aptos clock says it's time.
        assert!(now >= capsule.unlock_time, E_NOT_YET_TIME);

        capsule.time_key
    }

    /// Return public capsule metadata (safe to call at any time).
    ///
    /// @returns (unlock_time, author, recipient, blob_id, blob_name, created_at, recipient_bound)
    #[view]
    public fun get_capsule_info(
        registry_addr: address,
        capsule_id: u64,
    ): (u64, address, address, vector<u8>, vector<u8>, u64, bool) acquires CapsuleStore {
        assert!(exists<CapsuleStore>(registry_addr), E_STORE_NOT_FOUND);
        let store = borrow_global<CapsuleStore>(registry_addr);
        assert!(table::contains(&store.capsules, capsule_id), E_CAPSULE_NOT_FOUND);

        let c = table::borrow(&store.capsules, capsule_id);
        (c.unlock_time, c.author, c.recipient, c.blob_id, c.blob_name, c.created_at, c.recipient_bound)
    }

    /// Return total number of capsules ever sealed.
    #[view]
    public fun get_capsule_count(registry_addr: address): u64 acquires CapsuleStore {
        assert!(exists<CapsuleStore>(registry_addr), E_STORE_NOT_FOUND);
        borrow_global<CapsuleStore>(registry_addr).capsule_count
    }

    /// Check whether a capsule is currently unlocked.
    #[view]
    public fun is_unlocked(registry_addr: address, capsule_id: u64): bool acquires CapsuleStore {
        assert!(exists<CapsuleStore>(registry_addr), E_STORE_NOT_FOUND);
        let store = borrow_global<CapsuleStore>(registry_addr);
        assert!(table::contains(&store.capsules, capsule_id), E_CAPSULE_NOT_FOUND);
        timestamp::now_seconds() >= table::borrow(&store.capsules, capsule_id).unlock_time
    }

    /// Look up a wallet's registered public key.
    /// Aborts with E_PUBKEY_NOT_FOUND if that address has never registered one.
    #[view]
    public fun get_pubkey(registry_addr: address, user: address): vector<u8> acquires PubkeyRegistry {
        assert!(exists<PubkeyRegistry>(registry_addr), E_STORE_NOT_FOUND);
        let reg = borrow_global<PubkeyRegistry>(registry_addr);
        assert!(table::contains(&reg.pubkeys, user), E_PUBKEY_NOT_FOUND);
        *table::borrow(&reg.pubkeys, user)
    }

    /// Check whether a wallet has registered a public key yet.
    #[view]
    public fun has_pubkey(registry_addr: address, user: address): bool acquires PubkeyRegistry {
        assert!(exists<PubkeyRegistry>(registry_addr), E_STORE_NOT_FOUND);
        table::contains(&borrow_global<PubkeyRegistry>(registry_addr).pubkeys, user)
    }

    // ── Test-only helpers ─────────────────────────────────────────────────────
    #[test_only]
    use aptos_framework::account::create_account_for_test;

    #[test(aptos_framework = @aptos_framework, deployer = @shelby_capsule)]
    fun test_seal_and_unlock(
        aptos_framework: &signer,
        deployer: &signer,
    ) acquires CapsuleStore {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        create_account_for_test(signer::address_of(deployer));
        init_module(deployer);

        let registry = signer::address_of(deployer);
        let time_key = b"test_key_32_bytes_padded_to_fit!";
        let unlock_in = timestamp::now_seconds() + 100;

        seal_capsule(
            deployer,
            time_key,
            unlock_in,
            @0x0,
            b"0xabcdef",
            b"capsule/test.bin",
            false,
            registry,
        );

        // Fast-forward past unlock time
        timestamp::fast_forward_seconds(101);

        let retrieved = get_time_key(registry, 0);
        assert!(retrieved == time_key, 999);
    }

    #[test(aptos_framework = @aptos_framework, deployer = @shelby_capsule, user = @0x123)]
    fun test_register_and_lookup_pubkey(
        aptos_framework: &signer,
        deployer: &signer,
        user: &signer,
    ) acquires PubkeyRegistry {
        timestamp::set_time_has_started_for_testing(aptos_framework);
        create_account_for_test(signer::address_of(deployer));
        create_account_for_test(signer::address_of(user));
        init_module(deployer);

        let registry = signer::address_of(deployer);
        let key = b"32_byte_x25519_pubkey_goes_here!";

        register_pubkey(user, key, registry);
        let retrieved = get_pubkey(registry, signer::address_of(user));
        assert!(retrieved == key, 998);
        assert!(has_pubkey(registry, signer::address_of(user)), 997);
    }
}
