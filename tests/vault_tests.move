// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module vault::vault_tests;

use std::option;
use std::unit_test::{Self, assert_eq};
use sui::{bag, borrow, derived_object, event, test_scenario};
use vault::vault::{
    Self,
    PluginAuthorizedEvent,
    PluginRevokedEvent,
    Vault,
    VaultAdminCap,
    VaultCapabilityRestoredEvent,
    VaultCapabilityWithdrawnEvent,
    VaultCreatedEvent,
    VaultRegistryCreatedEvent,
    VaultRegistry,
};
use vault::witness::{Self, Witness};

const ENotVaultAdmin: u64 = 0;
const EPluginAlreadyAuthorized: u64 = 1;
const EPluginNotAuthorized: u64 = 2;
const EPluginsRemain: u64 = 3;
const EVaultEmpty: u64 = 4;
const EWrongCapability: u64 = 5;
const EWrongBorrow: u64 = 0;
const EWrongValue: u64 = 1;
const EOptionIsSet: u64 = 0x40000;
const EOptionNotSet: u64 = 0x40001;

public struct TestCap has key, store {
    id: UID,
}

public struct OtherCap has key, store {
    id: UID,
}

fun new_test_cap(ctx: &mut TxContext): TestCap {
    TestCap { id: object::new(ctx) }
}

fun new_vault(
    registry: &mut VaultRegistry,
    ctx: &mut TxContext,
): (Vault<TestCap>, VaultAdminCap<TestCap>) {
    vault::new(registry, new_test_cap(ctx), ctx)
}

fun fixture(
    ctx: &mut TxContext,
): (VaultRegistry, Vault<TestCap>, VaultAdminCap<TestCap>) {
    let mut registry = vault::new_registry_for_testing(ctx);
    let (vault, cap) = new_vault(&mut registry, ctx);
    (registry, vault, cap)
}

fun authorize(vault: &mut Vault<TestCap>, cap: &VaultAdminCap<TestCap>) {
    vault.authorize_plugin(cap, witness::new())
}

fun destroy_vaulted_cap(vaulted_cap: TestCap) {
    let TestCap { id } = vaulted_cap;
    id.delete();
}

fun discard<T>(value: T) {
    unit_test::destroy(value)
}

// === Canonical derivation and lifecycle ===

#[test]
fun ids_are_deterministic_and_type_separated() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let vaulted_cap = new_test_cap(ctx);
    let vaulted_cap_id = object::id(&vaulted_cap);
    let expected_vault = vault::derived_address<TestCap>(&registry, vaulted_cap_id);
    let expected_cap = vault::cap_address_for_testing(expected_vault.to_id());
    let other_type_vault = vault::derived_address<OtherCap>(&registry, vaulted_cap_id);
    let second_vaulted_cap = new_test_cap(ctx);
    let second_cap_vault = vault::derived_address<TestCap>(&registry, object::id(&second_vaulted_cap));

    let (vault, cap) = vault::new(&mut registry, vaulted_cap, ctx);

    assert_eq!(object::id(&vault).to_address(), expected_vault);
    assert_eq!(object::id(&cap).to_address(), expected_cap);
    assert_eq!(vault.vaulted_cap_id(), vaulted_cap_id);
    assert!(expected_vault != other_type_vault);
    assert!(expected_vault != second_cap_vault);

    discard(second_vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun full_state_machine_cycle_preserves_exact_capability() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vaulted_cap_id = vault.vaulted_cap_id();
    let vault_id = object::id(&vault);
    let admin_id = object::id(&cap);
    let plugins_id = object::id(vault.authorized_plugins());
    // P(0) -> P(1) -> B(1) -> P(1) -> P(0) -> E -> P(0) -> B(0) -> P(0).
    assert!(vault.is_active());
    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    authorize(&mut vault, &cap);
    assert_eq!(bag::length(vault.authorized_plugins()), 1);
    let (vaulted_cap, receipt) = vault.borrow_as_plugin(witness::new());
    assert_eq!(object::id(&vaulted_cap), vaulted_cap_id);
    vault.put_back(vaulted_cap, receipt);
    vault.revoke_plugin<TestCap, Witness>(&cap);

    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    assert!(!vault.is_active());
    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    assert_eq!(object::id(&vaulted_cap), vaulted_cap_id);

    vault.restore_vaulted_cap(&cap, vaulted_cap, ctx);
    assert!(vault.is_active());
    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    assert_eq!(object::id(&vault), vault_id);
    assert_eq!(object::id(&cap), admin_id);
    assert_eq!(object::id(vault.authorized_plugins()), plugins_id);
    let (vaulted_cap, receipt) = vault.borrow_as_admin(&cap);
    assert_eq!(object::id(&vaulted_cap), vaulted_cap_id);
    vault.put_back(vaulted_cap, receipt);

    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun withdraw_restore_and_use_can_share_one_ptb() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vaulted_cap_id = vault.vaulted_cap_id();

    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    vault.restore_vaulted_cap(&cap, vaulted_cap, ctx);
    let (vaulted_cap, receipt) = vault.borrow_as_admin(&cap);
    assert_eq!(object::id(&vaulted_cap), vaulted_cap_id);
    vault.put_back(vaulted_cap, receipt);

    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = derived_object::EObjectAlreadyExists)]
fun withdrawn_capability_cannot_claim_its_vault_again() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault, cap) = new_vault(&mut registry, ctx);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    let (duplicate, duplicate_admin) = vault::new(&mut registry, vaulted_cap, ctx);
    discard(duplicate_admin);
    discard(duplicate);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun registry_and_vault_are_shared_across_transactions() {
    let owner = @0xA;
    let mut scenario = test_scenario::begin(owner);
    vault::init_for_testing(scenario.ctx());

    scenario.next_tx(owner);
    let mut registry = scenario.take_shared<VaultRegistry>();
    let (vault, cap) = new_vault(&mut registry, scenario.ctx());
    test_scenario::return_shared(registry);
    vault.share();
    transfer::public_transfer(cap, owner);

    scenario.next_tx(owner);
    let mut vault = scenario.take_shared<Vault<TestCap>>();
    let cap = scenario.take_from_sender<VaultAdminCap<TestCap>>();
    authorize(&mut vault, &cap);
    let (vaulted_cap, receipt) = vault.borrow_as_plugin(witness::new());
    vault.put_back(vaulted_cap, receipt);
    vault.revoke_plugin<TestCap, Witness>(&cap);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    vault.restore_vaulted_cap(&cap, vaulted_cap, scenario.ctx());
    test_scenario::return_shared(vault);
    scenario.return_to_sender(cap);

    scenario.end();
}

#[test]
fun registry_and_vault_creation_identify_objects_and_sharing_is_silent() {
    let owner = @0xA;
    let mut scenario = test_scenario::begin(owner);
    vault::init_for_testing(scenario.ctx());

    assert_eq!(event::events_by_type<VaultRegistryCreatedEvent>().length(), 1);
    let (registry_id, shared) = vault::registry_created_event_fields(
        &event::events_by_type<VaultRegistryCreatedEvent>()[0],
    );
    assert!(shared);

    scenario.next_tx(owner);
    let mut registry = scenario.take_shared<VaultRegistry>();
    assert_eq!(registry_id, object::id(&registry).to_address());
    let (vault, cap) = new_vault(&mut registry, scenario.ctx());
    let vault_id = object::id(&vault).to_address();
    let vaulted_cap_id = vault.vaulted_cap_id().to_address();
    test_scenario::return_shared(registry);
    let event_count = event::num_events();
    vault.share();
    assert_eq!(event::num_events(), event_count);
    transfer::public_transfer(cap, owner);

    let created = event::events_by_type<VaultCreatedEvent<TestCap>>();
    assert_eq!(created.length(), 1);
    let (created_registry, created_vault, created_vaulted_cap, _, _, count, active, available) =
        vault::vault_created_event_ids(&created[0]);
    assert_eq!(created_registry, registry_id);
    assert_eq!(created_vault, vault_id);
    assert_eq!(created_vaulted_cap, vaulted_cap_id);
    assert_eq!(count, 0);
    assert!(active && available);
    assert_eq!(event::num_events(), 1);

    scenario.next_tx(owner);
    let vault = scenario.take_shared<Vault<TestCap>>();
    let cap = scenario.take_from_sender<VaultAdminCap<TestCap>>();
    assert_eq!(object::id(&vault).to_address(), vault_id);
    assert_eq!(vault.vaulted_cap_id().to_address(), vaulted_cap_id);
    assert!(vault.is_active());
    discard(cap);
    discard(vault);
    scenario.end();
}

#[test]
fun authorization_events_snapshot_each_typed_entry() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vault_id = object::id(&vault).to_address();
    let vaulted_cap_id = vault.vaulted_cap_id().to_address();
    let admin_id = object::id(&cap).to_address();
    let plugins_id = object::id(vault.authorized_plugins()).to_address();

    authorize(&mut vault, &cap);
    vault.authorize_plugin(&cap, 0u64);
    vault.revoke_plugin<TestCap, Witness>(&cap);
    vault.revoke_plugin<TestCap, u64>(&cap);

    let witness_authorized = event::events_by_type<PluginAuthorizedEvent<TestCap, Witness>>();
    let (event_vault, event_vaulted_cap, event_cap, event_plugins, count, authorized) =
        vault::plugin_authorized_event_vault_id(&witness_authorized[0]);
    assert_eq!(event_vault, vault_id);
    assert_eq!(event_vaulted_cap, vaulted_cap_id);
    assert_eq!(event_cap, admin_id);
    assert_eq!(event_plugins, plugins_id);
    assert_eq!(count, 1);
    assert!(authorized);

    let integer_authorized = event::events_by_type<PluginAuthorizedEvent<TestCap, u64>>();
    let (_, _, _, _, count, authorized) =
        vault::plugin_authorized_event_vault_id(&integer_authorized[0]);
    assert_eq!(count, 2);
    assert!(authorized);

    let witness_revoked = event::events_by_type<PluginRevokedEvent<TestCap, Witness>>();
    let (_, _, _, _, count, authorized) =
        vault::plugin_revoked_event_vault_id(&witness_revoked[0]);
    assert_eq!(count, 1);
    assert!(!authorized);

    let integer_revoked = event::events_by_type<PluginRevokedEvent<TestCap, u64>>();
    let (_, _, _, _, count, authorized) =
        vault::plugin_revoked_event_vault_id(&integer_revoked[0]);
    assert_eq!(count, 0);
    assert!(!authorized);

    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun successful_borrow_and_return_is_silent() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vaulted_cap_id = vault.vaulted_cap_id().to_address();
    authorize(&mut vault, &cap);

    let events_before_plugin_borrow = event::num_events();
    let (vaulted_cap, receipt) = vault.borrow_as_plugin(witness::new());
    assert_eq!(object::id(&vaulted_cap).to_address(), vaulted_cap_id);
    assert_eq!(event::num_events(), events_before_plugin_borrow);
    vault.put_back(vaulted_cap, receipt);
    assert_eq!(event::num_events(), events_before_plugin_borrow);
    assert!(vault.is_active());

    let events_before_admin_borrow = event::num_events();
    let (vaulted_cap, receipt) = vault.borrow_as_admin(&cap);
    assert_eq!(object::id(&vaulted_cap).to_address(), vaulted_cap_id);
    assert_eq!(event::num_events(), events_before_admin_borrow);
    vault.put_back(vaulted_cap, receipt);
    assert_eq!(event::num_events(), events_before_admin_borrow);
    assert!(vault.is_active());

    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun lifecycle_events_identify_the_derived_objects() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let expected_registry = object::id(&registry).to_address();
    let vaulted_cap = new_test_cap(ctx);
    let vaulted_cap_id = object::id(&vaulted_cap);
    let expected_vault = vault::derived_address<TestCap>(&registry, vaulted_cap_id);
    let expected_vaulted_cap = vaulted_cap_id.to_address();
    let (mut vault, cap) = vault::new(&mut registry, vaulted_cap, ctx);
    let expected_cap = object::id(&cap).to_address();
    let expected_plugins = object::id(vault.authorized_plugins()).to_address();
    authorize(&mut vault, &cap);
    vault.revoke_plugin<TestCap, Witness>(&cap);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    vault.restore_vaulted_cap(&cap, vaulted_cap, ctx);

    assert_eq!(event::num_events(), 5);
    assert_eq!(event::events_by_type<VaultCreatedEvent<TestCap>>().length(), 1);
    assert_eq!(event::events_by_type<PluginAuthorizedEvent<TestCap, Witness>>().length(), 1);
    assert_eq!(event::events_by_type<PluginRevokedEvent<TestCap, Witness>>().length(), 1);
    assert_eq!(event::events_by_type<VaultCapabilityWithdrawnEvent<TestCap>>().length(), 1);
    assert_eq!(event::events_by_type<VaultCapabilityRestoredEvent<TestCap>>().length(), 1);
    let (
        created_registry,
        created_vault,
        created_vaulted_cap,
        created_cap,
        created_plugins,
        created_count,
        created_active,
        created_available,
    ) = vault::vault_created_event_ids(
        &event::events_by_type<VaultCreatedEvent<TestCap>>()[0],
    );
    assert_eq!(created_registry, expected_registry);
    assert_eq!(created_vault, expected_vault);
    assert_eq!(created_vaulted_cap, expected_vaulted_cap);
    assert_eq!(created_cap, expected_cap);
    assert_eq!(created_plugins, expected_plugins);
    assert_eq!(created_count, 0);
    assert!(created_active);
    assert!(created_available);
    let (authorized_vault, authorized_cap, authorized_admin, authorized_plugins, authorized_count, authorized) =
        vault::plugin_authorized_event_vault_id(
            &event::events_by_type<PluginAuthorizedEvent<TestCap, Witness>>()[0],
        );
    assert_eq!(authorized_vault, expected_vault);
    assert_eq!(authorized_cap, expected_vaulted_cap);
    assert_eq!(authorized_admin, expected_cap);
    assert_eq!(authorized_plugins, expected_plugins);
    assert_eq!(authorized_count, 1);
    assert!(authorized);
    let (revoked_vault, revoked_cap, revoked_admin, revoked_plugins, revoked_count, revoked) =
        vault::plugin_revoked_event_vault_id(
            &event::events_by_type<PluginRevokedEvent<TestCap, Witness>>()[0],
        );
    assert_eq!(revoked_vault, expected_vault);
    assert_eq!(revoked_cap, expected_vaulted_cap);
    assert_eq!(revoked_admin, expected_cap);
    assert_eq!(revoked_plugins, expected_plugins);
    assert_eq!(revoked_count, 0);
    assert!(!revoked);
    let (withdrawn_vault, withdrawn_vaulted_cap, withdrawn_admin, withdrawn_active, withdrawn_available) =
        vault::capability_withdrawn_event_vault_id(
            &event::events_by_type<VaultCapabilityWithdrawnEvent<TestCap>>()[0],
        );
    assert_eq!(withdrawn_vault, expected_vault);
    assert_eq!(withdrawn_vaulted_cap, expected_vaulted_cap);
    assert_eq!(withdrawn_admin, expected_cap);
    assert!(!withdrawn_active);
    assert!(!withdrawn_available);
    let (restored_vault, restored_cap, restored_admin, restored_active, restored_available) =
        vault::capability_restored_event_vault_id(
            &event::events_by_type<VaultCapabilityRestoredEvent<TestCap>>()[0],
        );
    assert_eq!(restored_vault, expected_vault);
    assert_eq!(restored_cap, expected_vaulted_cap);
    assert_eq!(restored_admin, expected_cap);
    assert!(restored_active);
    assert!(restored_available);
    let _ = vault::derived_address<TestCap>(&registry, vaulted_cap_id);
    let _ = vault.vaulted_cap_id();
    let _ = vault.is_active();
    let _ = vault.authorized_plugins();
    let _ = vault.is_plugin_authorized<TestCap, Witness>();
    assert_eq!(event::num_events(), 5);

    discard(cap);
    discard(vault);
    discard(registry);
}

// === Active and inactive-state guards ===

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun empty_vault_cannot_be_borrowed_by_admin() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    let (borrowed, receipt) = vault.borrow_as_admin(&cap);
    discard(receipt);
    discard(borrowed);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun empty_vault_cannot_be_borrowed_by_plugin() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    let (borrowed, receipt) = vault.borrow_as_plugin(witness::new());
    discard(receipt);
    discard(borrowed);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EVaultEmpty, location = vault)]
fun empty_vault_cannot_authorize_plugin() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    authorize(&mut vault, &cap);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun capability_cannot_be_withdrawn_twice() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    let second = vault.withdraw_vaulted_cap(&cap);
    discard(second);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EOptionIsSet, location = option)]
fun active_vault_cannot_be_restored() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let (vaulted_cap, receipt) = vault.borrow_as_admin(&cap);
    vault.restore_vaulted_cap(&cap, vaulted_cap, ctx);
    discard(receipt);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EWrongCapability, location = vault)]
fun wrong_capability_cannot_restore_empty_vault() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let original_vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    vault.restore_vaulted_cap(&cap, new_test_cap(ctx), ctx);
    discard(original_vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

// === Complete plugin-set invariant ===

#[test, expected_failure(abort_code = EPluginsRemain, location = vault)]
fun one_authorized_plugin_blocks_withdrawal() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    authorize(&mut vault, &cap);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginsRemain, location = vault)]
fun every_authorized_plugin_must_be_removed_before_withdrawal() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    authorize(&mut vault, &cap);
    vault.authorize_plugin(&cap, 0u64);
    assert_eq!(bag::length(vault.authorized_plugins()), 2);
    vault.revoke_plugin<TestCap, Witness>(&cap);
    assert_eq!(bag::length(vault.authorized_plugins()), 1);
    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun revoking_every_plugin_allows_withdrawal() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    authorize(&mut vault, &cap);
    vault.authorize_plugin(&cap, 0u64);
    vault.revoke_plugin<TestCap, Witness>(&cap);
    vault.revoke_plugin<TestCap, u64>(&cap);
    assert_eq!(bag::length(vault.authorized_plugins()), 0);

    let vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    assert!(!vault.is_active());

    destroy_vaulted_cap(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

// === Authorization and administrative isolation ===

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun unauthorized_plugin_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let (vaulted_cap, receipt) = vault.borrow_as_plugin(witness::new());
    discard(receipt);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginAlreadyAuthorized, location = vault)]
fun plugin_cannot_be_authorized_twice() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    authorize(&mut vault, &cap);
    authorize(&mut vault, &cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun absent_plugin_cannot_be_revoked() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    vault.revoke_plugin<TestCap, Witness>(&cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun revoked_plugin_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    authorize(&mut vault, &cap);
    vault.revoke_plugin<TestCap, Witness>(&cap);
    let (vaulted_cap, receipt) = vault.borrow_as_plugin(witness::new());
    discard(receipt);
    discard(vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun authorization_is_scoped_to_one_vault() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, cap_b) = new_vault(&mut registry, ctx);
    authorize(&mut vault_a, &cap_a);

    assert!(vault_a.is_plugin_authorized<TestCap, Witness>());
    assert!(!vault_b.is_plugin_authorized<TestCap, Witness>());
    let (vaulted_cap, receipt) = vault_a.borrow_as_plugin(witness::new());
    vault_a.put_back(vaulted_cap, receipt);

    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

#[test]
fun authorization_can_be_revoked_during_a_live_borrow() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    authorize(&mut vault, &cap);

    let (vaulted_cap, receipt) = vault.borrow_as_plugin(witness::new());
    vault.revoke_plugin<TestCap, Witness>(&cap);
    vault.put_back(vaulted_cap, receipt);

    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    assert!(vault.is_active());
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test]
fun plugin_can_be_authorized_during_a_live_admin_borrow() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let (vaulted_cap, receipt) = vault.borrow_as_admin(&cap);

    authorize(&mut vault, &cap);
    vault.put_back(vaulted_cap, receipt);

    assert_eq!(bag::length(vault.authorized_plugins()), 1);
    assert!(vault.is_active());
    vault.revoke_plugin<TestCap, Witness>(&cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_authorize_plugin() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, cap_b) = new_vault(&mut registry, ctx);
    authorize(&mut vault_a, &cap_b);
    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_revoke_plugin() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, cap_b) = new_vault(&mut registry, ctx);
    authorize(&mut vault_a, &cap_a);
    vault_a.revoke_plugin<TestCap, Witness>(&cap_b);
    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, cap_b) = new_vault(&mut registry, ctx);
    let (vaulted_cap, receipt) = vault_a.borrow_as_admin(&cap_b);
    discard(receipt);
    discard(vaulted_cap);
    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_withdraw_capability() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, cap_b) = new_vault(&mut registry, ctx);
    let vaulted_cap = vault_a.withdraw_vaulted_cap(&cap_b);
    discard(vaulted_cap);
    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_restore_capability() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, cap_b) = new_vault(&mut registry, ctx);
    let vaulted_cap = vault_a.withdraw_vaulted_cap(&cap_a);
    vault_a.restore_vaulted_cap(&cap_b, vaulted_cap, ctx);
    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

// === Hot-potato integrity ===

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun capability_cannot_be_borrowed_twice_in_one_ptb() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let (first_vaulted_cap, first_receipt) = vault.borrow_as_admin(&cap);
    let (second_vaulted_cap, second_receipt) = vault.borrow_as_admin(&cap);
    discard(second_receipt);
    discard(second_vaulted_cap);
    discard(first_receipt);
    discard(first_vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun capability_cannot_be_withdrawn_during_a_live_borrow() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    let (borrowed_vaulted_cap, receipt) = vault.borrow_as_admin(&cap);
    let withdrawn_vaulted_cap = vault.withdraw_vaulted_cap(&cap);
    discard(withdrawn_vaulted_cap);
    discard(receipt);
    discard(borrowed_vaulted_cap);
    discard(cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EWrongValue, location = borrow)]
fun borrowed_capability_cannot_be_substituted() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (mut vault_b, cap_b) = new_vault(&mut registry, ctx);
    let (vaulted_cap_a, receipt_a) = vault_a.borrow_as_admin(&cap_a);
    let (vaulted_cap_b, receipt_b) = vault_b.borrow_as_admin(&cap_b);
    vault_a.put_back(vaulted_cap_b, receipt_a);
    vault_b.put_back(vaulted_cap_a, receipt_b);
    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = EWrongBorrow, location = borrow)]
fun borrowed_capability_cannot_be_returned_to_another_vault() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, cap_a) = new_vault(&mut registry, ctx);
    let (mut vault_b, cap_b) = new_vault(&mut registry, ctx);
    let (vaulted_cap_a, receipt_a) = vault_a.borrow_as_admin(&cap_a);
    vault_b.put_back(vaulted_cap_a, receipt_a);
    discard(cap_b);
    discard(vault_b);
    discard(cap_a);
    discard(vault_a);
    discard(registry);
}

// === Witness policy ===

#[test]
fun admin_can_authorize_any_drop_witness_type() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, cap) = fixture(ctx);
    vault.authorize_plugin(&cap, 0u64);
    assert!(vault.is_plugin_authorized<TestCap, u64>());
    let (vaulted_cap, receipt) = vault.borrow_as_plugin(0u64);
    vault.put_back(vaulted_cap, receipt);
    vault.revoke_plugin<TestCap, u64>(&cap);
    discard(cap);
    discard(vault);
    discard(registry);
}
