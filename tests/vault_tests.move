// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module vault::vault_tests;

use generic_witness::witness as generic_witness;
use std::unit_test::assert_eq;
use sui::borrow;
use sui::test_scenario;
use vault::vault::{Self, Vault, VaultAdminCap};
use vault::witness::{Self, Witness};

const ENotVaultAdmin: u64 = 0;
const EPluginAlreadyAuthorized: u64 = 1;
const EPluginNotAuthorized: u64 = 2;
const EPluginsRemain: u64 = 3;
const EInvalidWitnessType: u64 = 4;
const EWrongBorrow: u64 = 0;
const EWrongValue: u64 = 1;

public struct OtherWitness() has drop;

public struct TestCap has key, store {
    id: UID,
}

fun new_vault(ctx: &mut TxContext): (Vault<TestCap>, VaultAdminCap<TestCap>) {
    vault::new(TestCap { id: object::new(ctx) }, ctx)
}

fun authorize(vault: &mut Vault<TestCap>, admin_cap: &VaultAdminCap<TestCap>) {
    vault.authorize_plugin(admin_cap, witness::new())
}

fun destroy_cap(cap: TestCap) {
    let TestCap { id } = cap;
    id.delete();
}

fun destroy_empty(vault: Vault<TestCap>, admin_cap: VaultAdminCap<TestCap>) {
    destroy_cap(vault.destroy(admin_cap))
}

#[test]
fun plugin_can_borrow_and_return_full_capability() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    let vault_id = vault.id();
    let authorized_plugins_id = vault.authorized_plugins_id();

    assert!(authorized_plugins_id != vault_id);
    assert_eq!(vault.authorized_plugin_count(), 0);
    assert!(!vault.is_plugin_authorized<TestCap, Witness>());
    authorize(&mut vault, &admin_cap);
    assert_eq!(vault.authorized_plugin_count(), 1);
    assert!(vault.is_plugin_authorized<TestCap, Witness>());

    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    let cap_id = object::id(&cap);
    vault.put_back(cap, receipt);

    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    assert_eq!(vault.authorized_plugin_count(), 0);
    assert!(!vault.is_plugin_authorized<TestCap, Witness>());
    let cap = vault.destroy(admin_cap);
    assert_eq!(object::id(&cap), cap_id);
    destroy_cap(cap);
}

#[test]
fun administrator_can_borrow_and_return_full_capability() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    assert_eq!(admin_cap.vault_id(), vault.id());

    let (cap, receipt) = vault.borrow_as_admin(&admin_cap);
    let cap_id = object::id(&cap);
    vault.put_back(cap, receipt);

    let cap = vault.destroy(admin_cap);
    assert_eq!(object::id(&cap), cap_id);
    destroy_cap(cap);
}

#[test]
fun vault_recovers_the_exact_custodied_capability() {
    let ctx = &mut tx_context::dummy();
    let cap = TestCap { id: object::new(ctx) };
    let cap_id = object::id(&cap);
    let (vault, admin_cap) = vault::new(cap, ctx);

    let cap = vault.destroy(admin_cap);
    assert_eq!(object::id(&cap), cap_id);
    destroy_cap(cap);
}

#[test]
fun shared_vault_can_be_administered_across_transactions() {
    let owner = @0xA;
    let mut scenario = test_scenario::begin(owner);
    let (vault, admin_cap) = new_vault(scenario.ctx());
    vault.share();
    transfer::public_transfer(admin_cap, owner);

    scenario.next_tx(owner);
    let mut vault = scenario.take_shared<Vault<TestCap>>();
    let admin_cap = scenario.take_from_sender<VaultAdminCap<TestCap>>();
    authorize(&mut vault, &admin_cap);
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    vault.put_back(cap, receipt);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    let cap = vault.destroy(admin_cap);
    destroy_cap(cap);
    scenario.end();
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun unauthorized_plugin_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    vault.put_back(cap, receipt);
    destroy_cap(vault.destroy(admin_cap));
}

#[test, expected_failure(abort_code = EPluginAlreadyAuthorized, location = vault)]
fun plugin_cannot_be_authorized_twice() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    authorize(&mut vault, &admin_cap);
    authorize(&mut vault, &admin_cap);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    destroy_empty(vault, admin_cap);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun absent_plugin_cannot_be_revoked() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    destroy_empty(vault, admin_cap);
}

#[test, expected_failure(abort_code = EPluginNotAuthorized, location = vault)]
fun revoked_plugin_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    authorize(&mut vault, &admin_cap);
    vault.revoke_plugin<TestCap, Witness>(&admin_cap);
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    vault.put_back(cap, receipt);
    destroy_empty(vault, admin_cap);
}

#[test, expected_failure(abort_code = EPluginsRemain, location = vault)]
fun vault_with_authorized_plugin_cannot_be_destroyed() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    authorize(&mut vault, &admin_cap);
    let cap = vault.destroy(admin_cap);
    destroy_cap(cap);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_authorize_plugin() {
    let ctx = &mut tx_context::dummy();
    let (mut vault_a, admin_cap_a) = new_vault(ctx);
    let (vault_b, admin_cap_b) = new_vault(ctx);
    authorize(&mut vault_a, &admin_cap_b);
    destroy_empty(vault_a, admin_cap_a);
    destroy_empty(vault_b, admin_cap_b);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_revoke_plugin() {
    let ctx = &mut tx_context::dummy();
    let (mut vault_a, admin_cap_a) = new_vault(ctx);
    let (vault_b, admin_cap_b) = new_vault(ctx);
    authorize(&mut vault_a, &admin_cap_a);
    vault_a.revoke_plugin<TestCap, Witness>(&admin_cap_b);
    vault_a.revoke_plugin<TestCap, Witness>(&admin_cap_a);
    destroy_empty(vault_a, admin_cap_a);
    destroy_empty(vault_b, admin_cap_b);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_admin_cap_cannot_borrow_capability() {
    let ctx = &mut tx_context::dummy();
    let (mut vault_a, admin_cap_a) = new_vault(ctx);
    let (vault_b, admin_cap_b) = new_vault(ctx);
    let (cap, receipt) = vault_a.borrow_as_admin(&admin_cap_b);
    vault_a.put_back(cap, receipt);
    destroy_empty(vault_a, admin_cap_a);
    destroy_empty(vault_b, admin_cap_b);
}

#[test, expected_failure(abort_code = EWrongValue, location = borrow)]
fun borrowed_capability_cannot_be_substituted() {
    let ctx = &mut tx_context::dummy();
    let (mut vault_a, admin_cap_a) = new_vault(ctx);
    let (mut vault_b, admin_cap_b) = new_vault(ctx);
    let (cap_a, receipt_a) = vault_a.borrow_as_admin(&admin_cap_a);
    let (cap_b, receipt_b) = vault_b.borrow_as_admin(&admin_cap_b);
    vault_a.put_back(cap_b, receipt_a);
    vault_b.put_back(cap_a, receipt_b);
    destroy_empty(vault_a, admin_cap_a);
    destroy_empty(vault_b, admin_cap_b);
}

#[test, expected_failure(abort_code = EWrongBorrow, location = borrow)]
fun borrowed_capability_cannot_be_returned_to_another_vault() {
    let ctx = &mut tx_context::dummy();
    let (mut vault_a, admin_cap_a) = new_vault(ctx);
    let (mut vault_b, admin_cap_b) = new_vault(ctx);
    let (cap_a, receipt_a) = vault_a.borrow_as_admin(&admin_cap_a);
    vault_b.put_back(cap_a, receipt_a);
    destroy_empty(vault_a, admin_cap_a);
    destroy_empty(vault_b, admin_cap_b);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun noncanonical_witness_type_cannot_be_authorized() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    vault.authorize_plugin(&admin_cap, OtherWitness());
    destroy_empty(vault, admin_cap);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun primitive_witness_type_cannot_be_authorized() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    vault.authorize_plugin(&admin_cap, 0u64);
    destroy_empty(vault, admin_cap);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun wrong_witness_datatype_cannot_be_authorized() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    vault.authorize_plugin(&admin_cap, witness::new_wrong_name());
    destroy_empty(vault, admin_cap);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun generic_witness_type_cannot_be_authorized() {
    let ctx = &mut tx_context::dummy();
    let (mut vault, admin_cap) = new_vault(ctx);
    vault.authorize_plugin(&admin_cap, generic_witness::new<u64>());
    destroy_empty(vault, admin_cap);
}

#[test]
fun authorization_is_scoped_to_one_vault() {
    let ctx = &mut tx_context::dummy();
    let (mut vault_a, admin_cap_a) = new_vault(ctx);
    let (vault_b, admin_cap_b) = new_vault(ctx);
    authorize(&mut vault_a, &admin_cap_a);

    assert!(vault_a.is_plugin_authorized<TestCap, Witness>());
    assert!(!vault_b.is_plugin_authorized<TestCap, Witness>());
    let (cap, receipt) = vault_a.borrow_as_plugin(witness::new());
    vault_a.put_back(cap, receipt);

    vault_a.revoke_plugin<TestCap, Witness>(&admin_cap_a);
    destroy_cap(vault_a.destroy(admin_cap_a));
    destroy_cap(vault_b.destroy(admin_cap_b));
}
