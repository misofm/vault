// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Generic capability custody and plugin authorization.
///
/// `Vault<Cap>` is a permanent, deterministically addressed shell that can hold
/// one exact capability in a Sui `Referent`. An authorized plugin receives the
/// whole capability temporarily, paired with a hot-potato `Borrow` receipt that
/// forces the same capability back into the same vault before the transaction
/// can finish. Plugin authorization is represented by a typed dynamic field in
/// the vault's `Bag`.
module vault::vault;

use sui::bag::{Self, Bag};
use sui::borrow::{Self, Borrow, Referent};
use sui::derived_object;
use sui::event::emit;

// === Errors ===

/// The supplied vault admin capability belongs to a different vault.
const ENotVaultAdmin: u64 = 0;
/// A plugin with this witness type is already authorized.
const EPluginAlreadyAuthorized: u64 = 1;
/// No authorization exists for this plugin witness type.
const EPluginNotAuthorized: u64 = 2;
/// Every plugin authorization must be revoked before the capability can be withdrawn.
const EPluginsRemain: u64 = 3;
/// The Vault does not currently hold its capability.
const EVaultEmpty: u64 = 4;
/// Only the exact capability used to derive this Vault may be restored.
const EWrongCapability: u64 = 5;

// === Structs ===

/// The singleton namespace from which every Vault ID is derived.
public struct VaultRegistry has key {
    id: UID,
}

/// Custodies one capability and the typed authorization records for plugins.
///
/// `Vault` intentionally lacks `store`: only this module can share it, and no
/// production API can delete it. `cap_id` permanently binds the shell to the
/// exact capability from which its ID was derived. An empty Vault can only be
/// restored with that same capability object.
public struct Vault<Cap: key + store> has key {
    id: UID,
    cap_id: ID,
    cap: Option<Referent<Cap>>,
    authorized_plugins: Bag,
}

/// Authorizes administration and direct administrative borrowing for one vault.
/// Custody and transfer policy can be composed outside this module.
public struct VaultAdminCap<phantom Cap: key + store> has key, store {
    id: UID,
    vault_id: ID,
}

/// Derives one canonical Vault for an exact capability object.
public struct VaultKey<phantom Cap: key + store>(ID) has copy, drop, store;

/// Derives the canonical administrator capability from its Vault.
public struct VaultAdminCapKey() has copy, drop, store;

/// The typed key for a plugin authorization record.
///
/// Its fields are private, so only this module can create a key. `Witness` is
/// phantom: every witness type produces a distinct dynamic-field name without
/// storing a witness value.
public struct AuthorizedPluginKey<phantom Witness: drop>() has copy, drop, store;

// === Events ===

public struct VaultCreatedEvent<phantom Cap> has copy, drop {
    vault_id: ID,
    cap_id: ID,
}

public struct PluginAuthorizedEvent<phantom Cap, phantom Witness> has copy, drop {
    vault_id: ID,
}

public struct PluginRevokedEvent<phantom Cap, phantom Witness> has copy, drop {
    vault_id: ID,
}

public struct VaultCapabilityWithdrawnEvent<phantom Cap> has copy, drop {
    vault_id: ID,
}

public struct VaultCapabilityRestoredEvent<phantom Cap> has copy, drop {
    vault_id: ID,
}

// === Lifecycle ===

fun init(ctx: &mut TxContext) {
    let registry = VaultRegistry { id: object::new(ctx) };
    transfer::share_object(registry)
}

/// Custody `cap` in its canonical permanent Vault and create the canonical
/// vault-specific administrator capability.
public fun new<Cap: key + store>(
    registry: &mut VaultRegistry,
    cap: Cap,
    ctx: &mut TxContext,
): (Vault<Cap>, VaultAdminCap<Cap>) {
    let cap_id = object::id(&cap);
    let mut vault_id = derived_object::claim(
        &mut registry.id,
        VaultKey<Cap>(cap_id),
    );
    let vault_id_value = vault_id.to_inner();
    let vault_admin_cap = VaultAdminCap<Cap> {
        id: derived_object::claim(&mut vault_id, VaultAdminCapKey()),
        vault_id: vault_id_value,
    };

    emit(VaultCreatedEvent<Cap> {
        vault_id: vault_id_value,
        cap_id,
    });

    (
        Vault {
            id: vault_id,
            cap_id,
            cap: option::some(borrow::new(cap, ctx)),
            authorized_plugins: bag::new(ctx),
        },
        vault_admin_cap,
    )
}

/// Share a newly-created vault.
public fun share<Cap: key + store>(vault: Vault<Cap>) {
    transfer::share_object(vault)
}

/// Withdraw the exact capability while leaving its canonical Vault and
/// VaultAdminCap intact. Every plugin must be revoked first.
public fun withdraw_cap<Cap: key + store>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
): Cap {
    self.assert_admin(admin_cap);
    assert!(bag::is_empty(&self.authorized_plugins), EPluginsRemain);

    let cap = self.cap.extract().destroy();
    emit(VaultCapabilityWithdrawnEvent<Cap> {
        vault_id: object::id(self),
    });
    cap
}

/// Restore the exact capability used to derive this permanent Vault.
/// Restoring always starts from a clean plugin-authorization slate.
public fun restore_cap<Cap: key + store>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
    cap: Cap,
    ctx: &mut TxContext,
) {
    self.assert_admin(admin_cap);
    assert!(object::id(&cap) == self.cap_id, EWrongCapability);

    self.cap.fill(borrow::new(cap, ctx));
    emit(VaultCapabilityRestoredEvent<Cap> {
        vault_id: object::id(self),
    });
}

// === Plugin authorization ===

/// Authorize the plugin identified by this witness type.
public fun authorize_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
    _: Witness,
) {
    self.assert_admin(admin_cap);
    assert!(self.cap.is_some(), EVaultEmpty);
    let key = AuthorizedPluginKey<Witness>();
    assert!(
        !bag::contains(&self.authorized_plugins, key),
        EPluginAlreadyAuthorized,
    );
    bag::add(
        &mut self.authorized_plugins,
        key,
        true,
    );
    emit(PluginAuthorizedEvent<Cap, Witness> { vault_id: object::id(self) });
}

/// Revoke a plugin authorization without requiring cooperation from the plugin.
public fun revoke_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
) {
    self.assert_admin(admin_cap);
    let key = AuthorizedPluginKey<Witness>();
    assert!(bag::contains(&self.authorized_plugins, key), EPluginNotAuthorized);
    let _: bool = bag::remove(
        &mut self.authorized_plugins,
        key,
    );
    emit(PluginRevokedEvent<Cap, Witness> { vault_id: object::id(self) });
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
    let _: &bool = bag::borrow(
        &self.authorized_plugins,
        AuthorizedPluginKey<Witness>(),
    );
    self.cap.borrow_mut().borrow()
}

/// Temporarily lend the full custodied capability to the vault administrator.
public fun borrow_as_admin<Cap: key + store>(
    self: &mut Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
): (Cap, Borrow) {
    self.assert_admin(admin_cap);
    self.cap.borrow_mut().borrow()
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
    self.cap.borrow_mut().put_back(cap, receipt)
}

// === Views ===

/// Derive the canonical Vault address for `cap_id` in this registry.
public fun derived_address<Cap: key + store>(registry: &VaultRegistry, cap_id: ID): address {
    derived_object::derive_address(object::id(registry), VaultKey<Cap>(cap_id))
}

/// Vault governed by this administrator capability.
public fun vault_id<Cap: key + store>(self: &VaultAdminCap<Cap>): ID {
    self.vault_id
}

/// The exact capability object permanently assigned to this Vault.
public fun cap_id<Cap: key + store>(self: &Vault<Cap>): ID {
    self.cap_id
}

/// Whether this Vault is active.
///
/// An active Vault has an outer Referent. It remains active during a
/// transaction-local lease even though that Referent is temporarily empty.
public fun is_active<Cap: key + store>(self: &Vault<Cap>): bool {
    self.cap.is_some()
}

/// The immutable Bag containing typed plugin-authorization records.
public fun authorized_plugins<Cap: key + store>(self: &Vault<Cap>): &Bag {
    &self.authorized_plugins
}

/// Returns whether this witness type has an authorization record.
public fun is_plugin_authorized<Cap: key + store, Witness: drop>(self: &Vault<Cap>): bool {
    bag::contains(&self.authorized_plugins, AuthorizedPluginKey<Witness>())
}

// === Private helpers ===

fun assert_admin<Cap: key + store>(
    self: &Vault<Cap>,
    admin_cap: &VaultAdminCap<Cap>,
) {
    assert!(object::id(self) == admin_cap.vault_id, ENotVaultAdmin)
}

#[test_only]
public fun new_registry_for_testing(ctx: &mut TxContext): VaultRegistry {
    VaultRegistry { id: object::new(ctx) }
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx)
}

#[test_only]
public fun admin_cap_address_for_testing(vault_id: ID): address {
    derived_object::derive_address(vault_id, VaultAdminCapKey())
}

#[test_only]
public fun vault_created_event_ids<Cap>(event: &VaultCreatedEvent<Cap>): (ID, ID) {
    (event.vault_id, event.cap_id)
}

#[test_only]
public fun plugin_authorized_event_vault_id<Cap, Witness>(
    event: &PluginAuthorizedEvent<Cap, Witness>,
): ID {
    event.vault_id
}

#[test_only]
public fun plugin_revoked_event_vault_id<Cap, Witness>(
    event: &PluginRevokedEvent<Cap, Witness>,
): ID {
    event.vault_id
}

#[test_only]
public fun capability_withdrawn_event_vault_id<Cap>(
    event: &VaultCapabilityWithdrawnEvent<Cap>,
): ID {
    event.vault_id
}

#[test_only]
public fun capability_restored_event_vault_id<Cap>(
    event: &VaultCapabilityRestoredEvent<Cap>,
): ID {
    event.vault_id
}
