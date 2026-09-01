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
    let (vault, admin_cap) = new_vault(&mut registry, ctx);
    (registry, vault, admin_cap)
}

fun authorize(vault: &mut Vault<TestCap>, admin_cap: &VaultAdminCap<TestCap>) {
    vault.authorize_plugin(admin_cap, witness::new())
}

fun destroy_cap(cap: TestCap) {
    let TestCap { id } = cap;
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
    let cap = new_test_cap(ctx);
    let cap_id = object::id(&cap);
    let expected_vault = vault::derived_address<TestCap>(&registry, cap_id);
    let expected_admin = vault::admin_cap_address_for_testing(expected_vault.to_id());
    let other_type_vault = vault::derived_address<OtherCap>(&registry, cap_id);
    let second_cap = new_test_cap(ctx);
    let second_cap_vault = vault::derived_address<TestCap>(&registry, object::id(&second_cap));

    let (vault, admin_cap) = vault::new(&mut registry, cap, ctx);

    assert_eq!(object::id(&vault).to_address(), expected_vault);
    assert_eq!(object::id(&admin_cap).to_address(), expected_admin);
    assert_eq!(vault.cap_id(), cap_id);
    assert!(expected_vault != other_type_vault);
    assert!(expected_vault != second_cap_vault);

    discard(second_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test]
fun full_state_machine_cycle_preserves_exact_capability() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let cap_id = vault.cap_id();
    let vault_id = object::id(&vault);
    let admin_id = object::id(&admin_cap);
    let plugins_id = object::id(vault.authorized_plugins());
    // P(0) -> P(1) -> B(1) -> P(1) -> P(0) -> E -> P(0) -> B(0) -> P(0).
    assert!(vault.is_active());
    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    authorize(&mut vault, &admin_cap);
    assert_eq!(bag::length(vault.authorized_plugins()), 1);
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    assert_eq!(object::id(&cap), cap_id);
    vault.put_back(cap, receipt);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);

    let cap = vault.withdraw_cap(&admin_cap);
    assert!(!vault.is_active());
    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    assert_eq!(object::id(&cap), cap_id);

    vault.restore_cap(&admin_cap, cap, ctx);
    assert!(vault.is_active());
    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    assert_eq!(object::id(&vault), vault_id);
    assert_eq!(object::id(&admin_cap), admin_id);
    assert_eq!(object::id(vault.authorized_plugins()), plugins_id);
    let (cap, receipt) = vault.borrow_as_admin(&admin_cap);
    assert_eq!(object::id(&cap), cap_id);
    vault.put_back(cap, receipt);

    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test]
fun withdraw_restore_and_use_can_share_one_ptb() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let cap_id = vault.cap_id();

    let cap = vault.withdraw_cap(&admin_cap);
    vault.restore_cap(&admin_cap, cap, ctx);
    let (cap, receipt) = vault.borrow_as_admin(&admin_cap);
    assert_eq!(object::id(&cap), cap_id);
    vault.put_back(cap, receipt);

    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = derived_object::EObjectAlreadyExists)]
fun withdrawn_capability_cannot_claim_its_vault_again() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault, admin_cap) = new_vault(&mut registry, ctx);
    let cap = vault.withdraw_cap(&admin_cap);
    let (duplicate, duplicate_admin) = vault::new(&mut registry, cap, ctx);
    discard(duplicate_admin);
    discard(duplicate);
    discard(admin_cap);
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
    let (vault, admin_cap) = new_vault(&mut registry, scenario.ctx());
    test_scenario::return_shared(registry);
    vault.share();
    transfer::public_transfer(admin_cap, owner);

    scenario.next_tx(owner);
    let mut vault = scenario.take_shared<Vault<TestCap>>();
    let admin_cap = scenario.take_from_sender<VaultAdminCap<TestCap>>();
    authorize(&mut vault, &admin_cap);
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    vault.put_back(cap, receipt);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    let cap = vault.withdraw_cap(&admin_cap);
    vault.restore_cap(&admin_cap, cap, scenario.ctx());
    test_scenario::return_shared(vault);
    scenario.return_to_sender(admin_cap);

    scenario.end();
}

#[test]
fun lifecycle_events_identify_the_derived_objects() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let cap = new_test_cap(ctx);
    let cap_id = object::id(&cap);
    let expected_vault = vault::derived_address<TestCap>(&registry, cap_id).to_id();
    let (mut vault, admin_cap) = vault::new(&mut registry, cap, ctx);
    authorize(&mut vault, &admin_cap);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    let cap = vault.withdraw_cap(&admin_cap);
    vault.restore_cap(&admin_cap, cap, ctx);

    assert_eq!(event::num_events(), 5);
    assert_eq!(event::events_by_type<VaultCreatedEvent<TestCap>>().length(), 1);
    assert_eq!(event::events_by_type<PluginAuthorizedEvent<TestCap, Witness>>().length(), 1);
    assert_eq!(event::events_by_type<PluginRevokedEvent<TestCap, Witness>>().length(), 1);
    assert_eq!(event::events_by_type<VaultCapabilityWithdrawnEvent<TestCap>>().length(), 1);
    assert_eq!(event::events_by_type<VaultCapabilityRestoredEvent<TestCap>>().length(), 1);
    let (created_vault, created_cap) =
        vault::vault_created_event_ids(
            &event::events_by_type<VaultCreatedEvent<TestCap>>()[0],
        );
    assert_eq!(created_vault, expected_vault);
    assert_eq!(created_cap, cap_id);
    assert_eq!(
        vault::plugin_authorized_event_vault_id(
            &event::events_by_type<PluginAuthorizedEvent<TestCap, Witness>>()[0],
        ),
        expected_vault,
    );
    assert_eq!(
        vault::plugin_revoked_event_vault_id(
            &event::events_by_type<PluginRevokedEvent<TestCap, Witness>>()[0],
        ),
        expected_vault,
    );
    assert_eq!(
        vault::capability_withdrawn_event_vault_id(
            &event::events_by_type<VaultCapabilityWithdrawnEvent<TestCap>>()[0],
        ),
        expected_vault,
    );
    assert_eq!(
        vault::capability_restored_event_vault_id(
            &event::events_by_type<VaultCapabilityRestoredEvent<TestCap>>()[0],
        ),
        expected_vault,
    );

    discard(admin_cap);
    discard(vault);
    discard(registry);
}

// === Active and inactive-state guards ===

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun empty_vault_cannot_be_borrowed_by_admin() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let cap = vault.withdraw_cap(&admin_cap);
    let (borrowed, receipt) = vault.borrow_as_admin(&admin_cap);
    discard(receipt);
    discard(borrowed);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun empty_vault_cannot_be_borrowed_by_plugin() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let cap = vault.withdraw_cap(&admin_cap);
    let (borrowed, receipt) = vault.borrow_as_plugin(witness::new());
    discard(receipt);
    discard(borrowed);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EVaultEmpty, location = vault)]
fun empty_vault_cannot_authorize_plugin() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let cap = vault.withdraw_cap(&admin_cap);
    authorize(&mut vault, &admin_cap);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun capability_cannot_be_withdrawn_twice() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let cap = vault.withdraw_cap(&admin_cap);
    let second = vault.withdraw_cap(&admin_cap);
    discard(second);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EOptionIsSet, location = option)]
fun active_vault_cannot_be_restored() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let (cap, receipt) = vault.borrow_as_admin(&admin_cap);
    vault.restore_cap(&admin_cap, cap, ctx);
    discard(receipt);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EWrongCapability, location = vault)]
fun wrong_capability_cannot_restore_empty_vault() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let original_cap = vault.withdraw_cap(&admin_cap);
    vault.restore_cap(&admin_cap, new_test_cap(ctx), ctx);
    discard(original_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

// === Complete plugin-set invariant ===

#[test, expected_failure(abort_code = EPluginsRemain, location = vault)]
fun one_authorized_plugin_blocks_withdrawal() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    authorize(&mut vault, &admin_cap);
    let cap = vault.withdraw_cap(&admin_cap);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginsRemain, location = vault)]
fun every_authorized_plugin_must_be_removed_before_withdrawal() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    authorize(&mut vault, &admin_cap);
    vault.authorize_plugin(&admin_cap, 0u64);
    assert_eq!(bag::length(vault.authorized_plugins()), 2);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    assert_eq!(bag::length(vault.authorized_plugins()), 1);
    let cap = vault.withdraw_cap(&admin_cap);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test]
fun revoking_every_plugin_allows_withdrawal() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    authorize(&mut vault, &admin_cap);
    vault.authorize_plugin(&admin_cap, 0u64);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    vault.revoke_plugin<TestCap, u64>(&admin_cap);
    assert_eq!(bag::length(vault.authorized_plugins()), 0);

    let cap = vault.withdraw_cap(&admin_cap);
    assert!(!vault.is_active());

    destroy_cap(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

// === Authorization and administrative isolation ===

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun unauthorized_plugin_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    discard(receipt);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginAlreadyAuthorized, location = vault)]
fun plugin_cannot_be_authorized_twice() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    authorize(&mut vault, &admin_cap);
    authorize(&mut vault, &admin_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun absent_plugin_cannot_be_revoked() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun revoked_plugin_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    authorize(&mut vault, &admin_cap);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    discard(receipt);
    discard(cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test]
fun authorization_is_scoped_to_one_vault() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    authorize(&mut vault_a, &admin_cap_a);

    assert!(vault_a.is_plugin_authorized<TestCap, Witness>());
    assert!(!vault_b.is_plugin_authorized<TestCap, Witness>());
    let (cap, receipt) = vault_a.borrow_as_plugin(witness::new());
    vault_a.put_back(cap, receipt);

    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

#[test]
fun authorization_can_be_revoked_during_a_live_borrow() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    authorize(&mut vault, &admin_cap);

    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    vault.put_back(cap, receipt);

    assert_eq!(bag::length(vault.authorized_plugins()), 0);
    assert!(vault.is_active());
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test]
fun plugin_can_be_authorized_during_a_live_admin_borrow() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let (cap, receipt) = vault.borrow_as_admin(&admin_cap);

    authorize(&mut vault, &admin_cap);
    vault.put_back(cap, receipt);

    assert_eq!(bag::length(vault.authorized_plugins()), 1);
    assert!(vault.is_active());
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_authorize_plugin() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    authorize(&mut vault_a, &admin_cap_b);
    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_revoke_plugin() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    authorize(&mut vault_a, &admin_cap_a);
    vault_a.revoke_plugin<TestCap, Witness>(&admin_cap_b);
    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    let (cap, receipt) = vault_a.borrow_as_admin(&admin_cap_b);
    discard(receipt);
    discard(cap);
    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_withdraw_capability() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    let cap = vault_a.withdraw_cap(&admin_cap_b);
    discard(cap);
    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_restore_capability() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    let cap = vault_a.withdraw_cap(&admin_cap_a);
    vault_a.restore_cap(&admin_cap_b, cap, ctx);
    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

// === Hot-potato integrity ===

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun capability_cannot_be_borrowed_twice_in_one_ptb() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let (first_cap, first_receipt) = vault.borrow_as_admin(&admin_cap);
    let (second_cap, second_receipt) = vault.borrow_as_admin(&admin_cap);
    discard(second_receipt);
    discard(second_cap);
    discard(first_receipt);
    discard(first_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EOptionNotSet, location = option)]
fun capability_cannot_be_withdrawn_during_a_live_borrow() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    let (borrowed_cap, receipt) = vault.borrow_as_admin(&admin_cap);
    let withdrawn_cap = vault.withdraw_cap(&admin_cap);
    discard(withdrawn_cap);
    discard(receipt);
    discard(borrowed_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}

#[test, expected_failure(abort_code = EWrongValue, location = borrow)]
fun borrowed_capability_cannot_be_substituted() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (mut vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    let (cap_a, receipt_a) = vault_a.borrow_as_admin(&admin_cap_a);
    let (cap_b, receipt_b) = vault_b.borrow_as_admin(&admin_cap_b);
    vault_a.put_back(cap_b, receipt_a);
    vault_b.put_back(cap_a, receipt_b);
    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

#[test, expected_failure(abort_code = EWrongBorrow, location = borrow)]
fun borrowed_capability_cannot_be_returned_to_another_vault() {
    let ctx = &mut tx_context::dummy();
    let mut registry = vault::new_registry_for_testing(ctx);
    let (mut vault_a, admin_cap_a) = new_vault(&mut registry, ctx);
    let (mut vault_b, admin_cap_b) = new_vault(&mut registry, ctx);
    let (cap_a, receipt_a) = vault_a.borrow_as_admin(&admin_cap_a);
    vault_b.put_back(cap_a, receipt_a);
    discard(admin_cap_b);
    discard(vault_b);
    discard(admin_cap_a);
    discard(vault_a);
    discard(registry);
}

// === Witness policy ===

#[test]
fun admin_can_authorize_any_drop_witness_type() {
    let ctx = &mut tx_context::dummy();
    let (registry, mut vault, admin_cap) = fixture(ctx);
    vault.authorize_plugin(&admin_cap, 0u64);
    assert!(vault.is_plugin_authorized<TestCap, u64>());
    let (cap, receipt) = vault.borrow_as_plugin(0u64);
    vault.put_back(cap, receipt);
    vault.revoke_plugin<TestCap, u64>(&admin_cap);
    discard(admin_cap);
    discard(vault);
    discard(registry);
}
