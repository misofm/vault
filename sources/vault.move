// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module vault::vault;

use sui::bag::{Self, Bag};
use sui::borrow::{Self, Borrow, Referent};
use sui::derived_object;
use sui::event::emit;

// === Errors ===

const ENotVaultAdmin: u64 = 0;
const EPluginAlreadyAuthorized: u64 = 1;
const EPluginNotAuthorized: u64 = 2;
const EPluginsRemain: u64 = 3;
const EVaultEmpty: u64 = 4;
const EWrongCapability: u64 = 5;

// === Structs ===

public struct VaultRegistry has key {
    id: UID,
}

public struct Vault<Cap: key + store> has key {
    id: UID,
    vaulted_cap_id: ID,
    vaulted_cap: Option<Referent<Cap>>,
    authorized_plugins: Bag,
}

public struct VaultAdminCap<phantom Cap: key + store> has key, store {
    id: UID,
    vault_id: ID,
}

public struct VaultKey<phantom Cap: key + store>(ID) has copy, drop, store;

public struct VaultAdminCapKey() has copy, drop, store;

public struct AuthorizedPluginKey<phantom Witness: drop>() has copy, drop, store;

// === Events ===

public struct VaultRegistryCreatedEvent has copy, drop {
    registry_id: address,
    shared: bool,
}

public struct VaultCreatedEvent<phantom Cap> has copy, drop {
    registry_id: address,
    vault_id: address,
    vaulted_cap_id: address,
    cap_id: address,
    authorized_plugins_id: address,
    authorized_plugin_count: u64,
    active: bool,
    capability_available: bool,
}

public struct PluginAuthorizedEvent<phantom Cap, phantom Witness> has copy, drop {
    vault_id: address,
    vaulted_cap_id: address,
    cap_id: address,
    authorized_plugins_id: address,
    authorized_plugin_count: u64,
    authorized: bool,
}

public struct PluginRevokedEvent<phantom Cap, phantom Witness> has copy, drop {
    vault_id: address,
    vaulted_cap_id: address,
    cap_id: address,
    authorized_plugins_id: address,
    authorized_plugin_count: u64,
    authorized: bool,
}

public struct VaultCapabilityWithdrawnEvent<phantom Cap> has copy, drop {
    vault_id: address,
    vaulted_cap_id: address,
    cap_id: address,
    active: bool,
    capability_available: bool,
}

public struct VaultCapabilityRestoredEvent<phantom Cap> has copy, drop {
    vault_id: address,
    vaulted_cap_id: address,
    cap_id: address,
    active: bool,
    capability_available: bool,
}

// === Lifecycle ===

fun init(ctx: &mut TxContext) {
    let registry = VaultRegistry { id: object::new(ctx) };
    let registry_id = object::id(&registry).to_address();
    transfer::share_object(registry);
    emit(VaultRegistryCreatedEvent {
        registry_id,
        shared: true,
    });
}

public fun new<Cap: key + store>(
    registry: &mut VaultRegistry,
    vaulted_cap: Cap,
    ctx: &mut TxContext,
): (Vault<Cap>, VaultAdminCap<Cap>) {
    let registry_id = object::id(registry).to_address();
    let vaulted_cap_id = object::id(&vaulted_cap);
    let mut vault_id = derived_object::claim(
        &mut registry.id,
        VaultKey<Cap>(vaulted_cap_id),
    );
    let vault_id_value = vault_id.to_inner();
    let cap = VaultAdminCap<Cap> {
        id: derived_object::claim(&mut vault_id, VaultAdminCapKey()),
        vault_id: vault_id_value,
    };

    let vault = Vault {
        id: vault_id,
        vaulted_cap_id,
        vaulted_cap: option::some(borrow::new(vaulted_cap, ctx)),
        authorized_plugins: bag::new(ctx),
    };

    emit(VaultCreatedEvent<Cap> {
        registry_id,
        vault_id: vault_id_value.to_address(),
        vaulted_cap_id: vaulted_cap_id.to_address(),
        cap_id: object::id(&cap).to_address(),
        authorized_plugins_id: object::id(&vault.authorized_plugins).to_address(),
        authorized_plugin_count: bag::length(&vault.authorized_plugins),
        active: true,
        capability_available: true,
    });

    (vault, cap)
}

public fun share<Cap: key + store>(self: Vault<Cap>) {
    transfer::share_object(self);
}

public fun withdraw_vaulted_cap<Cap: key + store>(
    self: &mut Vault<Cap>,
    cap: &VaultAdminCap<Cap>,
): Cap {
    self.assert_admin(cap);
    assert!(bag::is_empty(&self.authorized_plugins), EPluginsRemain);

    let vaulted_cap = self.vaulted_cap.extract().destroy();
    emit(VaultCapabilityWithdrawnEvent<Cap> {
        vault_id: object::id(self).to_address(),
        vaulted_cap_id: self.vaulted_cap_id.to_address(),
        cap_id: object::id(cap).to_address(),
        active: false,
        capability_available: false,
    });
    vaulted_cap
}

public fun restore_vaulted_cap<Cap: key + store>(
    self: &mut Vault<Cap>,
    cap: &VaultAdminCap<Cap>,
    vaulted_cap: Cap,
    ctx: &mut TxContext,
) {
    self.assert_admin(cap);
    assert!(object::id(&vaulted_cap) == self.vaulted_cap_id, EWrongCapability);

    self.vaulted_cap.fill(borrow::new(vaulted_cap, ctx));
    emit(VaultCapabilityRestoredEvent<Cap> {
        vault_id: object::id(self).to_address(),
        vaulted_cap_id: self.vaulted_cap_id.to_address(),
        cap_id: object::id(cap).to_address(),
        active: true,
        capability_available: true,
    });
}

// === Plugin authorization ===

public fun authorize_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    cap: &VaultAdminCap<Cap>,
    _: Witness,
) {
    self.assert_admin(cap);
    assert!(self.vaulted_cap.is_some(), EVaultEmpty);
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
    emit(PluginAuthorizedEvent<Cap, Witness> {
        vault_id: object::id(self).to_address(),
        vaulted_cap_id: self.vaulted_cap_id.to_address(),
        cap_id: object::id(cap).to_address(),
        authorized_plugins_id: object::id(&self.authorized_plugins).to_address(),
        authorized_plugin_count: bag::length(&self.authorized_plugins),
        authorized: true,
    });
}

public fun revoke_plugin<Cap: key + store, Witness: drop>(
    self: &mut Vault<Cap>,
    cap: &VaultAdminCap<Cap>,
) {
    self.assert_admin(cap);
    let key = AuthorizedPluginKey<Witness>();
    assert!(bag::contains(&self.authorized_plugins, key), EPluginNotAuthorized);
    let _: bool = bag::remove(
        &mut self.authorized_plugins,
        key,
    );
    emit(PluginRevokedEvent<Cap, Witness> {
        vault_id: object::id(self).to_address(),
        vaulted_cap_id: self.vaulted_cap_id.to_address(),
        cap_id: object::id(cap).to_address(),
        authorized_plugins_id: object::id(&self.authorized_plugins).to_address(),
        authorized_plugin_count: bag::length(&self.authorized_plugins),
        authorized: false,
    });
}

// === Capability borrowing ===

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
    let (vaulted_cap, receipt) = self.vaulted_cap.borrow_mut().borrow();
    (vaulted_cap, receipt)
}

public fun borrow_as_admin<Cap: key + store>(
    self: &mut Vault<Cap>,
    cap: &VaultAdminCap<Cap>,
): (Cap, Borrow) {
    self.assert_admin(cap);
    let (vaulted_cap, receipt) = self.vaulted_cap.borrow_mut().borrow();
    (vaulted_cap, receipt)
}

public fun put_back<Cap: key + store>(
    self: &mut Vault<Cap>,
    vaulted_cap: Cap,
    receipt: Borrow,
) {
    self.vaulted_cap.borrow_mut().put_back(vaulted_cap, receipt);
}

// === Views ===

public fun derive_address<Cap: key + store>(registry: &VaultRegistry, vaulted_cap_id: ID): address {
    derived_object::derive_address(object::id(registry), VaultKey<Cap>(vaulted_cap_id))
}

public fun vaulted_cap_id<Cap: key + store>(self: &Vault<Cap>): ID {
    self.vaulted_cap_id
}

public fun is_active<Cap: key + store>(self: &Vault<Cap>): bool {
    self.vaulted_cap.is_some()
}

public fun authorized_plugins<Cap: key + store>(self: &Vault<Cap>): &Bag {
    &self.authorized_plugins
}

public fun is_plugin_authorized<Cap: key + store, Witness: drop>(self: &Vault<Cap>): bool {
    bag::contains(&self.authorized_plugins, AuthorizedPluginKey<Witness>())
}

// === Private helpers ===

fun assert_admin<Cap: key + store>(
    self: &Vault<Cap>,
    cap: &VaultAdminCap<Cap>,
) {
    assert!(object::id(self) == cap.vault_id, ENotVaultAdmin)
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
public fun cap_address_for_testing(vault_id: ID): address {
    derived_object::derive_address(vault_id, VaultAdminCapKey())
}

#[test_only]
public fun registry_created_event_fields(event: &VaultRegistryCreatedEvent): (address, bool) {
    (event.registry_id, event.shared)
}

#[test_only]
public fun vault_created_event_ids<Cap>(
    event: &VaultCreatedEvent<Cap>,
): (address, address, address, address, address, u64, bool, bool) {
    (
        event.registry_id,
        event.vault_id,
        event.vaulted_cap_id,
        event.cap_id,
        event.authorized_plugins_id,
        event.authorized_plugin_count,
        event.active,
        event.capability_available,
    )
}

#[test_only]
public fun plugin_authorized_event_vault_id<Cap, Witness>(
    event: &PluginAuthorizedEvent<Cap, Witness>,
): (address, address, address, address, u64, bool) {
    (
        event.vault_id,
        event.vaulted_cap_id,
        event.cap_id,
        event.authorized_plugins_id,
        event.authorized_plugin_count,
        event.authorized,
    )
}

#[test_only]
public fun plugin_revoked_event_vault_id<Cap, Witness>(
    event: &PluginRevokedEvent<Cap, Witness>,
): (address, address, address, address, u64, bool) {
    (
        event.vault_id,
        event.vaulted_cap_id,
        event.cap_id,
        event.authorized_plugins_id,
        event.authorized_plugin_count,
        event.authorized,
    )
}

#[test_only]
public fun capability_withdrawn_event_vault_id<Cap>(
    event: &VaultCapabilityWithdrawnEvent<Cap>,
): (address, address, address, bool, bool) {
    (
        event.vault_id,
        event.vaulted_cap_id,
        event.cap_id,
        event.active,
        event.capability_available,
    )
}

#[test_only]
public fun capability_restored_event_vault_id<Cap>(
    event: &VaultCapabilityRestoredEvent<Cap>,
): (address, address, address, bool, bool) {
    (
        event.vault_id,
        event.vaulted_cap_id,
        event.cap_id,
        event.active,
        event.capability_available,
    )
}
