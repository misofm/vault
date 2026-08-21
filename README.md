# Vault

Vault is a generic Sui Move primitive for custodying a high-value capability
without making it permanently available to application code.

`Vault<Cap>` accepts any `Cap: key + store`, stores it in Sui's
`Referent<Cap>`, and grants temporary access either to the matching vault
administrator or to an explicitly authorized plugin package.

> **Security:** Vault is intended to be published once and made immutable.
> Review [SECURITY.md](./SECURITY.md) before placing a production capability in
> custody.

## Security model

- **Exact-return leases.** Borrowing returns `(Cap, Borrow)`. `Borrow` has no
  abilities and can only be consumed by returning the same capability object to
  the originating referent in the same transaction.
- **Vault-specific administration.** `VaultAdminCap<Cap>` records its vault ID;
  a capability from another vault cannot authorize administration or borrowing.
- **Typed plugin authorization.** Each authorization is a private
  `AuthorizedPluginKey<Witness>` entry in the vault's `Bag`. The Bag is never
  exposed mutably.
- **Unilateral revocation.** The vault administrator can revoke a plugin without
  cooperation from that plugin.
- **Controlled recovery.** Destroying a vault consumes its matching admin cap,
  requires every plugin authorization to be removed, and returns the exact
  custodied capability.

Installing a plugin delegates the full authority of `Cap` for the duration of
each successful lease. Vault guarantees custody and authorization mechanics; it
does not prove that plugin bytecode is safe.

## API

| Function | Purpose |
|----------|---------|
| `new` | Wrap a capability and return `(Vault<Cap>, VaultAdminCap<Cap>)`. |
| `share` | Share a newly created vault. |
| `authorize_plugin` | Add an authorization for a canonical plugin witness. |
| `revoke_plugin` | Remove a plugin authorization. |
| `borrow_as_plugin` | Lease the capability to an authorized plugin. |
| `borrow_as_admin` | Lease the capability to the matching vault administrator. |
| `put_back` | Return the capability and consume its `Borrow` receipt. |
| `destroy` | Destroy an empty vault and recover its capability. |

Read-only functions expose vault identity and authorization status without
exposing the underlying `Bag` or capability.

## Plugin identity

Every plugin package uses one non-generic installation witness:

```move
module example_plugin::witness;

public struct Witness() has drop;

public(package) fun new(): Witness {
    Witness()
}
```

Vault requires the defining type name `0xpkg::witness::Witness`. Sui's defining
package ID identifies the package lineage, not a particular upgraded bytecode
version. Move also cannot prove that `drop` is the witness's only ability or
that no additional constructor is exported. Clients should therefore review
the package, its upgrade authority, and its witness module before installation.

Authority-bearing plugin endpoints should normally be `entry fun`s so another
Move package cannot use them as a composable authority trampoline.

## Example

```move
let (vault, vault_admin_cap) = vault::vault::new(admin_cap, ctx);
vault.share();
```

The administrator may then authorize plugin witnesses or use
`borrow_as_admin` for direct administrative operations.

## Development

```sh
sui move build
sui move test --coverage
```

## License

[Apache-2.0](./LICENSE)
