# Vault

Vault is a generic Sui Move primitive for permanent, discoverable capability
custody. A `Vault<Cap>` has a deterministic ID, temporarily lends its exact
capability through Sui's hot-potato `Borrow`, and can be emptied and restored
without deleting or changing the Vault object's identity.

> **Deployment warning:** this state model is incompatible with the published
> testnet v1 layout. Publish it as a fresh package with a fresh
> `VaultRegistry`; do not upgrade the v1 package. Republish dependent plugins
> against the new package ID.

## Design

- `init` creates and shares one `VaultRegistry`.
- `new(&mut registry, cap, ctx)` claims
  `VaultKey<Cap>(object::id(&cap))`, producing one canonical Vault for that
  exact capability object.
- The corresponding `VaultAdminCap<Cap>` is itself derived from the Vault with
  `VaultAdminCapKey()`.
- The Vault is a permanent `key`-only shell. Production code has no deletion
  path, and a derived claim can never be reclaimed.
- The optional `Referent<Cap>` is present while the Vault is active and absent
  after withdrawal. Only the original capability ID can restore it.
- Withdrawal requires the complete plugin-authorization Bag to be empty.
- `VaultAdminCap` has `key + store`, so transfer and custody policy can be
  composed outside this package.
- `is_active` reports whether the outer Referent is present. It remains true
  while a hot-potato lease temporarily empties that Referent in the same PTB.

## API

| Function | Purpose |
|---|---|
| `new` | Claim the canonical IDs and return `(Vault<Cap>, VaultAdminCap<Cap>)`. |
| `share` | Share a newly created Vault. |
| `authorize_plugin` | Add a plugin witness type while active. |
| `revoke_plugin` | Remove an authorization without plugin cooperation. |
| `borrow_as_plugin` | Lend the capability to an authorized plugin for this PTB. |
| `borrow_as_admin` | Lend the capability to the matching administrator. |
| `put_back` | Return the exact capability and consume its `Borrow`. |
| `withdraw_cap` | Return the capability while preserving the empty Vault shell. |
| `restore_cap` | Restore the exact capability originally assigned to the Vault. |
| `derived_address` | Derive a Vault address from registry, capability type, and cap ID. |

## Creation and discovery

```move
let (vault, vault_admin_cap) = vault::vault::new(
    &mut registry,
    release_admin_cap,
    ctx,
);
vault::vault::share(vault);
transfer::public_transfer(
    vault_admin_cap,
    ctx.sender(),
);
```

Given the registry and original `ReleaseAdminCap` ID, discovery is:

```move
let vault_address = vault::vault::derived_address<ReleaseAdminCap>(
    &registry,
    release_admin_cap_id,
);
```

Offchain consumers must still fetch the object at the derived address and
validate its exact type and stored `cap_id`. A derivable address is not proof
that creation has happened.

## Withdrawal and restoration

```move
// All plugin authorizations must already be revoked.
let release_admin_cap = vault.withdraw_cap(&vault_admin_cap);

// Later, restore the same object ID to the same permanent shell.
vault.restore_cap(&vault_admin_cap, release_admin_cap, ctx);
```

Once withdrawn, the raw capability can be transferred, wrapped, frozen,
destroyed, or lost according to its own APIs. Any action that makes the exact
object unavailable can leave the Vault permanently empty. Transfer the raw
capability and its matching VaultAdminCap together when control of the shell
should follow a sale.

## Plugin identity

Any type with `drop` can serve as a plugin witness. For example:

```move
module example_plugin::witness;

public struct Witness() has drop;

public(package) fun new(): Witness {
    Witness()
}
```

The full witness type is the authorization identity. Vault does not validate
its name, other abilities, constructor visibility, or issuer; the admin and
client are responsible for choosing an appropriate witness.

## Development

```sh
sui move build --build-env testnet
sui move test --build-env testnet
```

## License

[Apache-2.0](./LICENSE)
