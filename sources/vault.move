// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Generic capability custody and plugin authorization.
///
/// `Vault<Cap>` holds a capability in a Sui `Referent`. An authorized plugin
/// receives the whole capability temporarily, paired with a hot-potato
/// `Borrow` receipt that forces the same capability back into the same vault
/// before the transaction can finish. Plugin authorization is represented by a
/// typed dynamic field in the vault's `Bag`.
module vault::vault;

use std::type_name::{Self, TypeName};
use sui::bag::{Self, Bag};
use sui::borrow::{Self, Borrow, Referent};
use sui::event::emit;

// === Errors ===

/// The supplied vault admin capability belongs to a different vault.
const ENotVaultAdmin: u64 = 0;
/// A plugin with this witness type is already authorized.
const EPluginAlreadyAuthorized: u64 = 1;
/// No authorization exists for this plugin witness type.
const EPluginNotAuthorized: u64 = 2;
/// Every plugin authorization must be revoked before the vault can be destroyed.
const EPluginsRemain: u64 = 3;
/// Plugins must use the exact non-generic `0xpkg::witness::Witness` shape.
const EInvalidWitnessType: u64 = 4;

// === Structs ===

/// Custodies one capability and the typed authorization records for plugins.
///
/// `Vault` intentionally lacks `store`: only this module can share or destroy
/// it. The wrapped capability is never exposed except through a hot-potato
/// borrow that requires its exact return.
public struct Vault<Cap: key + store> has key {
    id: UID,
    cap: Referent<Cap>,
    authorized_plugins: Bag,
}

/// Authorizes administration and direct administrative borrowing for one vault.
public struct VaultAdminCap<phantom Cap: key + store> has key, store {
    id: UID,
    vault_id: ID,
}

/// The typed key for a plugin authorization record.
///
/// Its fields are private, so only this module can create a key. `Witness` is
/// phantom: every witness type produces a distinct dynamic-field name without
/// storing a witness value.
public struct AuthorizedPluginKey<phantom Witness: drop>() has copy, drop, store;

// === Events ===

public struct VaultCreatedEvent<phantom Cap> has copy, drop {
    vault_id: ID,
    vault_admin_cap_id: ID,
    wrapped_cap_id: ID,
    authorized_plugins_id: ID,
}

public struct PluginAuthorizedEvent<phantom Cap, phantom Witness> has copy, drop {
    vault_id: ID,
}

public struct PluginRevokedEvent<phantom Cap, phantom Witness> has copy, drop {
    vault_id: ID,
}

public struct VaultDestroyedEvent<phantom Cap> has copy, drop {
    vault_id: ID,
    wrapped_cap_id: ID,
}

// === Lifecycle ===

/// Custody `cap` and create its vault-specific administrator capability.
public fun new<Cap: key + store>(
    cap: Cap,
    ctx: &mut TxContext,
): (Vault<Cap>, VaultAdminCap<Cap>) {
    let vault_id = object::new(ctx);
    let vault_id_value = vault_id.to_inner();
    let wrapped_cap_id = object::id(&cap);
    let authorized_plugins = bag::new(ctx);
    let authorized_plugins_id = object::id(&authorized_plugins);
    let vault_admin_cap = VaultAdminCap<Cap> {
        id: object::new(ctx),
        vault_id: vault_id_value,
    };

    emit(VaultCreatedEvent<Cap> {
        vault_id: vault_id_value,
        vault_admin_cap_id: vault_admin_cap.id.to_inner(),
        wrapped_cap_id,
        authorized_plugins_id,
    });

    (
        Vault {
            id: vault_id,
            cap: borrow::new(cap, ctx),
            authorized_plugins,
        },
        vault_admin_cap,
    )
}

/// Share a newly-created vault.
public fun share<Cap: key + store>(vault: Vault<Cap>) {
    transfer::share_object(vault)
}

/// Destroy an empty vault and return the exact capability it custodied.
public fun destroy<Cap: key + store>(
    self: Vault<Cap>,
    admin_cap: VaultAdminCap<Cap>,
): Cap {
    self.assert_admin(&admin_cap);
    assert!(bag::is_empty(&self.authorized_plugins), EPluginsRemain);

    let Vault {
        id,
        cap,
        authorized_plugins,
    } = self;
    let VaultAdminCap {
        id: admin_cap_id,
        vault_id,
    } = admin_cap;
    let cap = borrow::destroy(cap);
    let wrapped_cap_id = object::id(&cap);
    authorized_plugins.destroy_empty();
    id.delete();
    admin_cap_id.delete();
    emit(VaultDestroyedEvent<Cap> { vault_id, wrapped_cap_id });
    cap
}

// === Plugin authorization ===

/// Authorize the package identified by its canonical `witness::Witness` type.
///
/// The witness is consumed here. A plugin should construct it with a
/// package-only `witness::new()` function.
public fun authorize_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
    _: Witness,
) {
    self.assert_admin(admin_cap);
    let _ = witness_type<Witness>();
    let key = AuthorizedPluginKey<Witness>();
    assert!(
        !bag::contains(&self.authorized_plugins, key),
        EPluginAlreadyAuthorized,
    );
    bag::add(&mut self.authorized_plugins, key, true);
    emit(PluginAuthorizedEvent<Cap, Witness> { vault_id: self.id() });
}

/// Revoke a plugin authorization without requiring cooperation from the plugin.
public fun revoke_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
) {
    self.assert_admin(admin_cap);
    let key = AuthorizedPluginKey<Witness>();
    assert!(bag::contains(&self.authorized_plugins, key), EPluginNotAuthorized);
    let _: bool = bag::remove(&mut self.authorized_plugins, key);
    emit(PluginRevokedEvent<Cap, Witness> { vault_id: self.id() });
}

// === Capability borrowing ===

/// Temporarily lend the full custodied capability to an authorized plugin.
///
/// `Borrow` has no abilities, so the exact capability must be returned through
/// `put_back` in this transaction.
public fun borrow_as_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    _: Witness,
): (Cap, Borrow) {
    assert!(
        bag::contains(&self.authorized_plugins, AuthorizedPluginKey<Witness>()),
        EPluginNotAuthorized,
    );
    borrow::borrow(&mut self.cap)
}

/// Temporarily lend the full custodied capability to the vault administrator.
public fun borrow_as_admin<Cap: key + store>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
): (Cap, Borrow) {
    self.assert_admin(admin_cap);
    borrow::borrow(&mut self.cap)
}

/// Return the exact capability borrowed from this vault.
///
/// No additional authorization is required: `Borrow` proves the originating
/// referent and capability object ID, and blocking return would harm liveness.
public fun put_back<Cap: key + store>(
    self: &mut Vault<Cap>,
    cap: Cap,
    receipt: Borrow,
) {
    borrow::put_back(&mut self.cap, cap, receipt)
}

// === Views ===

public fun id<Cap: key + store>(self: &Vault<Cap>): ID {
    self.id.to_inner()
}

public fun vault_id<Cap: key + store>(self: &VaultAdminCap<Cap>): ID {
    self.vault_id
}

/// The ID under which `AuthorizedPluginKey` records are dynamic fields.
public fun authorized_plugins_id<Cap: key + store>(self: &Vault<Cap>): ID {
    object::id(&self.authorized_plugins)
}

public fun authorized_plugin_count<Cap: key + store>(self: &Vault<Cap>): u64 {
    bag::length(&self.authorized_plugins)
}

/// Returns whether this witness type has an authorization record.
///
/// This deliberately does not validate the witness shape: arbitrary types
/// simply report false, while `authorize_plugin` is the only way to add one.
public fun is_plugin_authorized<Cap: key + store, Witness: drop>(self: &Vault<Cap>): bool {
    bag::contains(&self.authorized_plugins, AuthorizedPluginKey<Witness>())
}

// === Private helpers ===

fun witness_type<Witness: drop>(): TypeName {
    // The defining ID is the package version that first introduced Witness.
    // It persists through compatible plugin upgrades, so this validates a
    // package lineage rather than a single bytecode version.
    let witness = type_name::with_defining_ids<Witness>();
    assert!(!witness.is_primitive(), EInvalidWitnessType);
    assert!(witness.module_string().as_bytes() == &b"witness", EInvalidWitnessType);
    assert!(witness.datatype_string().as_bytes() == &b"Witness", EInvalidWitnessType);
    let type_parameters = b"<".to_ascii_string();
    assert!(
        witness.as_string().index_of(&type_parameters) == witness.as_string().length(),
        EInvalidWitnessType,
    );
    witness
}

fun assert_admin<Cap: key + store>(
    self: &Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
) {
    assert!(self.id() == admin_cap.vault_id, ENotVaultAdmin)
}
