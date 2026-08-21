// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Capability custody and plugin authorization for Miso protocol objects.
///
/// A `Vault<Cap>` wraps one protocol admin capability and records the canonical
/// `0xpkg::witness::Witness` types of the plugins installed against it. An
/// installed plugin proves its authority by calling its package-only
/// `witness::new()` and passing the resulting drop-only witness by value to one
/// of the `*_uid_mut` functions. That function consumes the witness, verifies
/// its type, and returns the host object's `&mut UID` without ever exposing the
/// wrapped admin capability.
///
/// Plugin packages should keep witness construction private. Their operational
/// transaction endpoints may be `entry fun`s when deliberately preventing
/// downstream Move packages from using the plugin as an authority trampoline.
module vault::vault;

use miso::composition::{Composition, CompositionAdminCap};
use miso::recording::{Recording, RecordingAdminCap};
use miso::release::{Release, ReleaseAdminCap};
use std::type_name::{Self, TypeName};
use sui::event::emit;
use sui::vec_set::{Self, VecSet};

// === Errors ===

/// The supplied vault admin capability belongs to a different vault.
const ENotVaultAdmin: u64 = 0;
/// A plugin with this witness type is already installed.
const EPluginAlreadyInstalled: u64 = 1;
/// No plugin with this witness type is installed.
const EPluginNotInstalled: u64 = 2;
/// Every plugin must be uninstalled before the vault can be destroyed.
const EPluginsRemain: u64 = 3;

// === Structs ===

/// Custodies a protocol admin capability and the installed plugin type names.
///
/// `Vault` intentionally lacks `store`: sharing and destruction remain under
/// this module's explicit API instead of being generally available through the
/// public transfer functions.
public struct Vault<Cap: key + store> has key {
    id: UID,
    cap: Cap,
    plugins: VecSet<TypeName>,
}

/// Authorizes installing and uninstalling plugins and recovering the wrapped
/// protocol admin capability from one particular vault.
public struct VaultAdminCap<phantom Cap: key + store> has key, store {
    id: UID,
    vault_id: ID,
}

// === Events ===

public struct VaultCreated<phantom Cap> has copy, drop {
    vault_id: ID,
    vault_admin_cap_id: ID,
}

public struct PluginInstalled<phantom Cap, phantom Witness> has copy, drop {
    vault_id: ID,
}

public struct PluginUninstalled<phantom Cap, phantom Witness> has copy, drop {
    vault_id: ID,
}

public struct VaultDestroyed<phantom Cap> has copy, drop {
    vault_id: ID,
}

// === Lifecycle ===

/// Wrap an admin capability and return the vault with its own admin cap.
/// The caller decides whether to share the vault and where to transfer the
/// returned `VaultAdminCap`.
public fun new<Cap: key + store>(
    cap: Cap,
    ctx: &mut TxContext,
): (Vault<Cap>, VaultAdminCap<Cap>) {
    let vault_id = object::new(ctx);
    let vault_id_value = vault_id.to_inner();
    let vault_admin_cap = VaultAdminCap<Cap> {
        id: object::new(ctx),
        vault_id: vault_id_value,
    };

    emit(VaultCreated<Cap> {
        vault_id: vault_id_value,
        vault_admin_cap_id: vault_admin_cap.id.to_inner(),
    });

    (
        Vault {
            id: vault_id,
            cap,
            plugins: vec_set::empty(),
        },
        vault_admin_cap,
    )
}

/// Share a newly-created vault.
public fun share<Cap: key + store>(vault: Vault<Cap>) {
    transfer::share_object(vault)
}

/// Destroy an empty vault and recover the exact admin capability it wrapped.
public fun destroy<Cap: key + store>(
    self: Vault<Cap>,
    admin_cap: VaultAdminCap<Cap>,
): Cap {
    self.assert_admin(&admin_cap);
    assert!(self.plugins.is_empty(), EPluginsRemain);

    let Vault { id, cap, plugins: _ } = self;
    let VaultAdminCap { id: admin_cap_id, vault_id } = admin_cap;
    id.delete();
    admin_cap_id.delete();
    emit(VaultDestroyed<Cap> { vault_id });
    cap
}

// === Plugin administration ===

/// Install the plugin identified by its canonical `witness::Witness` type.
///
/// The witness is received by value and dropped here. A plugin package should
/// expose an installation endpoint that constructs its private witness and
/// calls this function; the vault owner must participate with `admin_cap`.
public fun install_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
    _: Witness,
) {
    self.assert_admin(admin_cap);
    let witness = witness_type<Witness>();
    assert!(!self.plugins.contains(&witness), EPluginAlreadyInstalled);
    self.plugins.insert(witness);
    emit(PluginInstalled<Cap, Witness> { vault_id: self.id() });
}

/// Uninstall a plugin. No witness is required so the vault owner can always
/// revoke a plugin without cooperation from that plugin's package.
public fun uninstall_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
) {
    self.assert_admin(admin_cap);
    let witness = witness_type<Witness>();
    assert!(self.plugins.contains(&witness), EPluginNotInstalled);
    self.plugins.remove(&witness);
    emit(PluginUninstalled<Cap, Witness> { vault_id: self.id() });
}

// === Protocol authority ===

/// Return the composition's extension surface to an installed plugin.
/// `witness` is consumed in this function before the reference is returned.
public fun composition_uid_mut<CompositionShare, Witness: drop>(
    self: &Vault<CompositionAdminCap<CompositionShare>>,
    composition: &mut Composition<CompositionShare>,
    witness: Witness,
): &mut UID {
    self.assert_installed(witness);
    composition.uid_mut(&self.cap)
}

/// Return the recording's extension surface to an installed plugin.
/// `witness` is consumed in this function before the reference is returned.
public fun recording_uid_mut<RecordingShare, CompositionShare, Witness: drop>(
    self: &Vault<RecordingAdminCap<RecordingShare>>,
    recording: &mut Recording<RecordingShare, CompositionShare>,
    witness: Witness,
): &mut UID {
    self.assert_installed(witness);
    recording.uid_mut(&self.cap)
}

/// Return the release's extension surface to an installed plugin.
/// `witness` is consumed in this function before the reference is returned.
public fun release_uid_mut<Witness: drop>(
    self: &Vault<ReleaseAdminCap>,
    release: &mut Release,
    witness: Witness,
): &mut UID {
    self.assert_installed(witness);
    release.uid_mut(&self.cap)
}

// === Views ===

public fun id<Cap: key + store>(self: &Vault<Cap>): ID {
    self.id.to_inner()
}

public fun vault_id<Cap: key + store>(self: &VaultAdminCap<Cap>): ID {
    self.vault_id
}

public fun plugins<Cap: key + store>(self: &Vault<Cap>): &VecSet<TypeName> {
    &self.plugins
}

public fun has_plugin<Cap: key + store, Witness: drop>(self: &Vault<Cap>): bool {
    self.plugins.contains(&witness_type<Witness>())
}

// === Private helpers ===

fun witness_type<Witness: drop>(): TypeName {
    // Original IDs keep an installed plugin stable across compatible package
    // upgrades instead of treating each upgraded package version as a new one.
    type_name::with_original_ids<Witness>()
}

fun assert_admin<Cap: key + store>(
    self: &Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
) {
    assert!(self.id() == admin_cap.vault_id, ENotVaultAdmin)
}

fun assert_installed<Cap: key + store, Witness: drop>(
    self: &Vault<Cap>,
    _: Witness,
) {
    assert!(self.plugins.contains(&witness_type<Witness>()), EPluginNotInstalled)
}
