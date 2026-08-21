// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module vault::vault_tests;

use vault::vault::{Self, Vault, VaultAdminCap};
use vault::witness::{Self, Witness};
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

public struct OtherWitness() has drop;

public struct TestAdminCap has key, store {
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
    let (vault, vault_admin_cap) = vault::new(composition_admin_cap, ctx);
    (composition, vault, vault_admin_cap)
}

#[test]
fun shared_vault_can_be_administered_across_transactions() {
    let owner = @0xA;
    let mut scenario = test_scenario::begin(owner);
    let (vault, vault_admin_cap) = vault::new(
        TestAdminCap { id: object::new(scenario.ctx()) },
        scenario.ctx(),
    );
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
fun installed_plugin_reaches_recording_uid() {
    let ctx = &mut tx_context::dummy();
    let composition_id = test_helpers::fake_id(ctx);
    let (mut recording, recording_admin_cap) =
        recording::new_for_testing<RecordingShare, CompositionShare>(composition_id, ctx);
    let (mut vault, vault_admin_cap) = vault::new(recording_admin_cap, ctx);

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
    let (mut vault, vault_admin_cap) = vault::new(release_admin_cap, ctx);

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

#[test, expected_failure(abort_code = EPluginNotInstalled, location = vault)]
fun absent_plugin_cannot_be_uninstalled() {
    let ctx = &mut tx_context::dummy();
    let (composition, mut vault, vault_admin_cap) = new_composition_vault(ctx);
    vault.uninstall_plugin<CompositionAdminCap<CompositionShare>, OtherWitness>(&vault_admin_cap);
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
