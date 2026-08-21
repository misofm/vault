// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module vault::vault_tests;

use vault::vault::{Self, Vault, VaultAdminCap};
use vault::witness::{Self, Witness};
use generic_witness::witness as generic_witness;
use miso::composition::{Self, Composition, CompositionAdminCap};
use miso::recording::{Self, Recording, RecordingAdminCap};
use miso::release::{Self, Release, ReleaseAdminCap};
use miso::test_helpers::{Self, CompositionShare, RecordingShare};
use std::unit_test::{assert_eq, destroy};
use sui::test_scenario;

const ENotVaultAdmin: u64 = 0;
const EPluginAlreadyInstalled: u64 = 1;
const EPluginNotInstalled: u64 = 2;
const EPluginsRemain: u64 = 3;
const ETargetMismatch: u64 = 4;
const EInvalidWitnessType: u64 = 5;

public struct OtherWitness() has drop;

public struct TestAdminCap has key, store {
    id: UID,
}

public struct TestTarget has key {
    id: UID,
}

fun install<Cap: key + store>(
    vault: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
) {
    vault.install_plugin(admin_cap, witness::new())
}

fun new_composition_vault(
    ctx: &mut TxContext,
): (
    Composition<CompositionShare>,
    Vault<CompositionAdminCap<CompositionShare>>,
    VaultAdminCap<CompositionAdminCap<CompositionShare>>,
) {
    let (composition, composition_admin_cap) =
        composition::new_for_testing<CompositionShare>("Composition", 1000, ctx);
    let (vault, vault_admin_cap) = vault::new(&composition, composition_admin_cap, ctx);
    (composition, vault, vault_admin_cap)
}

#[test]
fun shared_vault_can_be_administered_across_transactions() {
    let owner = @0xA;
    let mut scenario = test_scenario::begin(owner);
    let target = TestTarget { id: object::new(scenario.ctx()) };
    let (vault, vault_admin_cap) = vault::new(
        &target,
        TestAdminCap { id: object::new(scenario.ctx()) },
        scenario.ctx(),
    );
    destroy(target);
    vault.share();
    transfer::public_transfer(vault_admin_cap, owner);

    scenario.next_tx(owner);
    let mut vault = scenario.take_shared<Vault<TestAdminCap>>();
    let vault_admin_cap = scenario.take_from_sender<VaultAdminCap<TestAdminCap>>();
    install(&mut vault, &vault_admin_cap);
    assert!(vault.has_plugin<TestAdminCap, Witness>());
    vault.uninstall_plugin<TestAdminCap, Witness>(&vault_admin_cap);

    let test_admin_cap = vault.destroy(vault_admin_cap);
    destroy(test_admin_cap);
    scenario.end();
}

#[test]
fun installed_plugin_reaches_composition_uid() {
    let ctx = &mut tx_context::dummy();
    let (mut composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);

    install(&mut vault, &vault_admin_cap);
    assert!(vault.has_plugin<CompositionAdminCap<CompositionShare>, Witness>());
    assert_eq!(vault.plugins().length(), 1);
    let composition_id = composition.id();
    assert_eq!(vault.target_id(), composition_id);
    assert_eq!(
        vault.composition_uid_mut(&mut composition, witness::new()).to_inner(),
        composition_id,
    );

    vault.uninstall_plugin<CompositionAdminCap<CompositionShare>, Witness>(&vault_admin_cap);
    let composition_admin_cap = vault.destroy(vault_admin_cap);
    destroy(composition);
    destroy(composition_admin_cap);
}

#[test]
fun vault_recovers_the_exact_wrapped_cap() {
    let ctx = &mut tx_context::dummy();
    let (composition, composition_admin_cap) =
        composition::new_for_testing<CompositionShare>("Composition", 1000, ctx);
    let wrapped_cap_id = object::id(&composition_admin_cap);
    let target_id = composition.id();
    let (vault, vault_admin_cap) = vault::new(&composition, composition_admin_cap, ctx);

    assert_eq!(vault.wrapped_cap_id(), wrapped_cap_id);
    assert_eq!(vault.target_id(), target_id);
    assert_eq!(vault_admin_cap.vault_id(), vault.id());
    let composition_admin_cap = vault.destroy(vault_admin_cap);
    assert_eq!(object::id(&composition_admin_cap), wrapped_cap_id);

    destroy(composition);
    destroy(composition_admin_cap);
}

#[test]
fun installed_plugin_reaches_recording_uid() {
    let ctx = &mut tx_context::dummy();
    let composition_id = test_helpers::fake_id(ctx);
    let (mut recording, recording_admin_cap) =
        recording::new_for_testing<RecordingShare, CompositionShare>(composition_id, ctx);
    let (mut vault, vault_admin_cap) = vault::new(&recording, recording_admin_cap, ctx);

    install(&mut vault, &vault_admin_cap);
    let recording_id = recording.id();
    assert_eq!(
        vault.recording_uid_mut(&mut recording, witness::new()).to_inner(),
        recording_id,
    );

    vault.uninstall_plugin<RecordingAdminCap<RecordingShare>, Witness>(&vault_admin_cap);
    let recording_admin_cap = vault.destroy(vault_admin_cap);
    destroy(recording);
    destroy(recording_admin_cap);
}

#[test]
fun installed_plugin_reaches_release_uid() {
    let ctx = &mut tx_context::dummy();
    let (mut release, release_admin_cap) = release::new_for_testing("Release", vector[], ctx);
    let (mut vault, vault_admin_cap) = vault::new(&release, release_admin_cap, ctx);

    install(&mut vault, &vault_admin_cap);
    let release_id = release.id();
    assert_eq!(
        vault.release_uid_mut(&mut release, witness::new()).to_inner(),
        release_id,
    );

    vault.uninstall_plugin<ReleaseAdminCap, Witness>(&vault_admin_cap);
    let release_admin_cap = vault.destroy(vault_admin_cap);
    destroy(release);
    destroy(release_admin_cap);
}

#[test, expected_failure(abort_code = EPluginNotInstalled, location = vault)]
fun uninstalled_plugin_cannot_reach_uid() {
    let ctx = &mut tx_context::dummy();
    let (mut composition, vault, vault_admin_cap) = new_composition_vault(ctx);
    vault.composition_uid_mut(&mut composition, witness::new());
    let composition_admin_cap = vault.destroy(vault_admin_cap);
    destroy(composition);
    destroy(composition_admin_cap);
}

#[test, expected_failure(abort_code = EPluginAlreadyInstalled, location = vault)]
fun plugin_cannot_be_installed_twice() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    install(&mut vault, &vault_admin_cap);
    install(&mut vault, &vault_admin_cap);
    vault.uninstall_plugin<CompositionAdminCap<CompositionShare>, Witness>(&vault_admin_cap);
    let composition_admin_cap = vault.destroy(vault_admin_cap);
    destroy(composition);
    destroy(composition_admin_cap);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_vault_admin_cap_cannot_install_plugin() {
    let ctx = &mut tx_context::dummy();
    let (composition_a, mut vault_a, vault_admin_cap_a) = new_composition_vault(ctx);
    let (composition_b, vault_b, vault_admin_cap_b) = new_composition_vault(ctx);
    install(&mut vault_a, &vault_admin_cap_b);
    vault_a.uninstall_plugin<CompositionAdminCap<CompositionShare>, Witness>(&vault_admin_cap_a);
    let composition_admin_cap_a = vault_a.destroy(vault_admin_cap_a);
    let composition_admin_cap_b = vault_b.destroy(vault_admin_cap_b);
    destroy(composition_a);
    destroy(composition_b);
    destroy(composition_admin_cap_a);
    destroy(composition_admin_cap_b);
}

#[test, expected_failure(abort_code = ENotVaultAdmin, location = vault)]
fun foreign_vault_admin_cap_cannot_recover_wrapped_cap() {
    let ctx = &mut tx_context::dummy();
    let (composition_a, vault_a, vault_admin_cap_a) = new_composition_vault(ctx);
    let (composition_b, vault_b, vault_admin_cap_b) = new_composition_vault(ctx);

    let composition_admin_cap_a = vault_a.destroy(vault_admin_cap_b);

    destroy(composition_admin_cap_a);
    destroy(vault_b);
    destroy(vault_admin_cap_a);
    destroy(composition_a);
    destroy(composition_b);
}

#[test, expected_failure(abort_code = EPluginNotInstalled, location = vault)]
fun absent_plugin_cannot_be_uninstalled() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    vault.uninstall_plugin<CompositionAdminCap<CompositionShare>, Witness>(&vault_admin_cap);
    let composition_admin_cap = vault.destroy(vault_admin_cap);
    destroy(composition);
    destroy(composition_admin_cap);
}

#[test, expected_failure(abort_code = EPluginsRemain, location = vault)]
fun vault_with_installed_plugin_cannot_be_destroyed() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    install(&mut vault, &vault_admin_cap);
    destroy(vault.destroy(vault_admin_cap));
    destroy(composition);
}

#[test, expected_failure(abort_code = ETargetMismatch, location = vault)]
fun composition_uid_access_is_bound_to_vault_target() {
    let ctx = &mut tx_context::dummy();
    let (composition_a, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    let (mut composition_b, composition_admin_cap_b) =
        composition::new_for_testing<CompositionShare>("Other Composition", 1000, ctx);
    install(&mut vault, &vault_admin_cap);

    vault.composition_uid_mut(&mut composition_b, witness::new());

    vault.uninstall_plugin<CompositionAdminCap<CompositionShare>, Witness>(&vault_admin_cap);
    let composition_admin_cap_a = vault.destroy(vault_admin_cap);
    destroy(composition_a);
    destroy(composition_b);
    destroy(composition_admin_cap_a);
    destroy(composition_admin_cap_b);
}

#[test, expected_failure(abort_code = ETargetMismatch, location = vault)]
fun recording_uid_access_is_bound_to_vault_target() {
    let ctx = &mut tx_context::dummy();
    let composition_id = test_helpers::fake_id(ctx);
    let (recording_a, recording_admin_cap_a) =
        recording::new_for_testing<RecordingShare, CompositionShare>(composition_id, ctx);
    let (mut recording_b, recording_admin_cap_b) =
        recording::new_for_testing<RecordingShare, CompositionShare>(composition_id, ctx);
    let (mut vault, vault_admin_cap) = vault::new(&recording_a, recording_admin_cap_a, ctx);
    install(&mut vault, &vault_admin_cap);

    vault.recording_uid_mut(&mut recording_b, witness::new());

    vault.uninstall_plugin<RecordingAdminCap<RecordingShare>, Witness>(&vault_admin_cap);
    let recording_admin_cap_a = vault.destroy(vault_admin_cap);
    destroy(recording_a);
    destroy(recording_b);
    destroy(recording_admin_cap_a);
    destroy(recording_admin_cap_b);
}

#[test, expected_failure(abort_code = ETargetMismatch, location = vault)]
fun release_uid_access_is_bound_to_vault_target() {
    let ctx = &mut tx_context::dummy();
    let (release_a, release_admin_cap_a) =
        release::new_for_testing("Release A", vector[], ctx);
    let (mut release_b, release_admin_cap_b) =
        release::new_for_testing("Release B", vector[], ctx);
    let (mut vault, vault_admin_cap) = vault::new(&release_a, release_admin_cap_a, ctx);
    install(&mut vault, &vault_admin_cap);

    vault.release_uid_mut(&mut release_b, witness::new());

    vault.uninstall_plugin<ReleaseAdminCap, Witness>(&vault_admin_cap);
    let release_admin_cap_a = vault.destroy(vault_admin_cap);
    destroy(release_a);
    destroy(release_b);
    destroy(release_admin_cap_a);
    destroy(release_admin_cap_b);
}

#[test, expected_failure(abort_code = EPluginNotInstalled, location = vault)]
fun plugin_installation_is_scoped_to_one_vault() {
    let ctx = &mut tx_context::dummy();
    let (composition_a, mut vault_a, vault_admin_cap_a) = new_composition_vault(ctx);
    let (mut composition_b, vault_b, vault_admin_cap_b) = new_composition_vault(ctx);
    install(&mut vault_a, &vault_admin_cap_a);

    vault_b.composition_uid_mut(&mut composition_b, witness::new());

    vault_a.uninstall_plugin<CompositionAdminCap<CompositionShare>, Witness>(&vault_admin_cap_a);
    let composition_admin_cap_a = vault_a.destroy(vault_admin_cap_a);
    let composition_admin_cap_b = vault_b.destroy(vault_admin_cap_b);
    destroy(composition_a);
    destroy(composition_b);
    destroy(composition_admin_cap_a);
    destroy(composition_admin_cap_b);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun noncanonical_witness_type_cannot_be_installed() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    vault.install_plugin(&vault_admin_cap, OtherWitness());

    vault.uninstall_plugin<CompositionAdminCap<CompositionShare>, OtherWitness>(&vault_admin_cap);
    let composition_admin_cap = vault.destroy(vault_admin_cap);
    destroy(composition);
    destroy(composition_admin_cap);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun primitive_witness_type_cannot_be_installed() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    vault.install_plugin(&vault_admin_cap, 0u64);

    vault.uninstall_plugin<CompositionAdminCap<CompositionShare>, u64>(&vault_admin_cap);
    let composition_admin_cap = vault.destroy(vault_admin_cap);
    destroy(composition);
    destroy(composition_admin_cap);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun wrong_witness_datatype_cannot_be_installed() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    vault.install_plugin(&vault_admin_cap, witness::new_wrong_name());

    destroy(vault);
    destroy(vault_admin_cap);
    destroy(composition);
}

#[test, expected_failure(abort_code = EInvalidWitnessType, location = vault)]
fun generic_witness_type_cannot_be_installed() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    vault.install_plugin(&vault_admin_cap, generic_witness::new<u64>());

    destroy(vault);
    destroy(vault_admin_cap);
    destroy(composition);
}
