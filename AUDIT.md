# Security Audit — `vault`

Audited at `1661860c698df7330f3a2d7e28dd009fba1d865` (2026-10-21). Scope: package `vault`, module `vault::vault` (`sources/vault.move`), with the Sui framework modules it relies on (`sui::borrow`, `sui::derived_object`, `sui::bag`).

## What it does

Permanent, deterministically addressed custody of one `key + store` object (the "vaulted cap"). The shared `Vault<Cap>` lends the exact object for the duration of one transaction through `sui::borrow`'s hot-potato `Borrow`, either to the holder of the matching `VaultAdminCap<Cap>` or to a plugin identified by a witness type. The admin can withdraw the object (leaving the shell) and later restore the same object. See [README](./README.md).

## Trust model

- **Anyone** may call `new` on the shared `VaultRegistry` for any object they own (`vault.move:108`), and `put_back` (`vault.move:264`); `put_back` is safe without authorization because `Borrow` (no abilities) already binds the exact `Referent` and object ID (`sui::borrow::put_back`).
- **`VaultAdminCap<Cap>` holder** (`key + store`, freely transferable): `authorize_plugin`, `revoke_plugin`, `borrow_as_admin`, `withdraw_vaulted_cap`, `restore_vaulted_cap`. Every one of these runs `assert_admin` (`vault.move:296-301`), which only compares `cap.vault_id` with the vault's ID; there is one canonical admin cap per vault, derived from the vault's UID (`vault.move:121`).
- **Plugin** (any code able to construct the authorized `Witness: drop` value): `borrow_as_plugin` (`vault.move:239`). The borrowed value is the whole capability; for the rest of the transaction the plugin can do anything the cap allows. Authorization is a `Bag` entry keyed by `AuthorizedPluginKey<Witness>` (`vault.move:42`), checked by type only.
- **Nobody** can: delete a `Vault`, transfer, wrap or freeze it (`key` only, no production deletion path), hold `&mut UID` of a vault or of the registry outside this module, re-claim a vault address once claimed (`derived_object::claim` aborts), restore an object other than the one the vault was derived from (`vault.move:175`), withdraw while any plugin is authorized (`vault.move:155`), or authorize a plugin while the vault is empty (`vault.move:195`).

## Findings

**VLT-01 — Low — Open — Plugin trust extends to the plugin package's upgrade authority.**
A plugin is identified purely by the `Witness` type (`vault.move:243-246`). A Move type's identity is bound to the original package ID and survives package upgrades, so after authorization the plugin publisher can change, through an upgrade, what the code constructing the witness does with the borrowed capability, without any new consent from the vault admin. The README's "Plugin identity" section describes the witness-only check but not this consequence. Suggested fix: document it and advise admins to authorize only plugins whose packages are immutable (UpgradeCap burned) or whose upgrade policy they trust.

**VLT-02 — Info — Accepted — Publicly constructible witness types make borrowing permissionless.**
`authorize_plugin` accepts any `Witness: drop` (`vault.move:189-192`), including primitives (`bool`, `u64`) or structs with public constructors. Probe: authorizing `bool` lets any caller `borrow_as_plugin(false)`. Documented in README ("Plugin identity"); the admin chooses the witness.

**VLT-03 — Info — Open — State-guard aborts surface `std::option` codes rather than vault codes.**
`borrow_as_admin` on an empty vault, a second borrow in the same transaction, and `withdraw_vaulted_cap` on an empty or currently-borrowed vault abort with `EOptionNotSet` (`0x40001`) from `std::option` (`vault.move:157`, `:260`); `restore_vaulted_cap` on an active vault aborts with `EOptionIsSet` (`0x40000`) (`vault.move:177`). `EVaultEmpty` is reachable only from `authorize_plugin` (`vault.move:195`). Shape only; behavior is correct. Suggested fix, if desired: explicit `assert!(self.vaulted_cap.is_some(), EVaultEmpty)` guards.

**VLT-04 — Info — Open — Redundant lookup in `borrow_as_plugin`.**
`vault.move:247-250` reads the `Bag` entry after `contains` has already been asserted at `:243-246`; the result is discarded. Dead code; remove.

**VLT-05 — Info — Accepted — No recovery from a lost `VaultAdminCap` or a lost withdrawn object.**
If the admin cap becomes unreachable, the vault's plugin set and custody state are frozen forever (authorized plugins keep borrowing). If the withdrawn object is destroyed or lost, the shell stays empty forever and its address can never be re-claimed (`derived_object::claim`, tested). Both follow from the permanent-shell design; the README documents the second.

**VLT-06 — Info — Accepted — Single shared registry is a creation bottleneck and grows without bound.**
Every `new` takes `&mut VaultRegistry` (`vault.move:109`) and adds one `Claimed` dynamic field to it (`sui::derived_object::claim`). All vault creation serializes through one shared object; the fields are never removed. Borrowing and administration do not touch the registry.

## Checked, no finding

- **Admin isolation:** every admin function calls `assert_admin` first (`vault.move:154,174,194,220,259`); foreign admin caps fail with `ENotVaultAdmin` in the suite (`tests/vault_tests.move:644-717`).
- **Hot-potato integrity:** `Borrow` has no abilities, so the borrowed object must return to the same `Referent` (`ref` address) with the same object ID (`sui::borrow::put_back`); swapped values and cross-vault returns abort with `EWrongValue`/`EWrongBorrow` (`tests/vault_tests.move:750-780`). Transferring, wrapping or destroying the borrowed object leaves an unconsumable `Borrow` and fails the transaction at compile/verification time.
- **No escape through the referent:** `withdraw_vaulted_cap` during a live borrow aborts (`destroy_some` on `None`); `restore_vaulted_cap` during a live borrow aborts (`fill` on `Some`); plugin revoke during a live borrow is allowed and the return still succeeds (`tests/vault_tests.move:611-625`). Probe: plugin borrow, revoke, then admin withdraw in one transaction aborts `EOptionNotSet`.
- **Empty-vault invariant:** withdrawal requires an empty plugin `Bag` and authorization requires an active vault, so an empty vault never has plugins; `borrow_as_plugin` on an empty vault therefore always aborts `EPluginNotAuthorized` (`tests/vault_tests.move:429-441`).
- **Derived IDs:** `VaultKey<Cap>(vaulted_cap_id)` is unique per (type, object ID), and object IDs are globally unique, so no two live objects collide; `VaultAdminCap` is derived from the vault UID with a constant key, so exactly one exists per vault. Probe: the registry ID is part of the derivation, so two registries give different vault addresses for the same object.
- **Object lifecycle:** `Vault` has `key` only, so a value returned by `new` can only be shared via `share` (`vault.move:146`) in the same transaction; it cannot be transferred, wrapped or frozen. `VaultCreatedEvent` therefore implies a shared vault. `VaultAdminCap` is `key + store` by design.
- **Dynamic fields:** no function exposes `&mut UID` of `Vault` or `VaultRegistry`; the only fields are the derived-object `Claimed` markers and the `Bag` entries added by this module.
- **Events:** one event per state change (`new`, `authorize_plugin`, `revoke_plugin`, `withdraw_vaulted_cap`, `restore_vaulted_cap`); borrows, returns and `share` are silent as documented. `authorized_plugin_count` is the post-change `Bag` length; `active`/`capability_available` snapshots match the new state (`tests/vault_tests.move:320-411`).
- **Composition:** nested custody works (probe: a `VaultAdminCap<TestCap>` vaulted in a second vault; the outer admin borrows the inner admin cap and uses it in the same transaction).
- **Limits:** no loops, no vectors; one `Bag` lookup or insert per call; one event per call. Plugin count is bounded only by admin actions and each must be revoked before withdrawal.
- **Money:** the package holds no funds.

## Operational requirements

- Choose a witness type with a module-private constructor; never authorize primitives or publicly constructible structs (VLT-02).
- Prefer immutable plugin packages or review the plugin publisher's upgrade policy before authorizing (VLT-01).
- Keep the `VaultAdminCap` and, after withdrawal, the raw object recoverable; both are unrecoverable by this package (VLT-05).
- Off-chain, treat a derivable vault address as a candidate only: fetch the object, check its type and `vaulted_cap_id` (README "Creation and discovery").
- `Published.toml` records a mainnet publish (version 1, toolchain 1.79.0) alongside the testnet v1 that the README declares layout-incompatible; confirm before use that the mainnet package is the current state model.

## Verification

- `sui move test --coverage --build-env testnet` (sui 1.82.1): 35/35 passed.
- `sui move coverage summary`: 100.00% for `vault::vault`.
- `sui move build --build-env mainnet` and `--build-env testnet`: both succeed with no warnings.
- Throwaway probe tests (not committed) for VLT-02, nested vaults, registry-dependent derivation, and borrow/revoke/withdraw ordering: all behaved as stated above.
