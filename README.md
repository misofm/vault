# Vault

`Vault<Cap>` is a small, protocol-agnostic custody primitive for any Sui
capability with `key + store`. It makes the capability available only as a
same-transaction, exact-return lease and lets a vault administrator authorize
specific plugin packages to obtain that lease.

The package is intended to be immutable. Consume its `UpgradeCap` with
`sui::package::make_immutable` in the publishing transaction before placing a
high-value capability in a vault. There is intentionally no application
versioning or migration API.

Read [SECURITY.md](./SECURITY.md) before use.

## Model

```move
public struct Vault<Cap: key + store> has key {
    id: UID,
    cap: Referent<Cap>,
    authorized_plugins: Bag,
}
```

`Referent<Cap>` returns `(Cap, Borrow)`. `Borrow` is a hot potato supplied by
Sui: it must be consumed in the same transaction, and `put_back` checks both
the exact capability object ID and the originating referent. `Bag` stores one
typed dynamic-field record per authorized plugin:

```move
AuthorizedPluginKey<plugin::witness::Witness>() -> true
```

Only the vault module can construct `AuthorizedPluginKey`, and the Bag is not
exposed mutably. Its `destroy_empty` invariant prevents destroying a vault that
would strand authorization records.

## Plugin shape

Every plugin package has `sources/witness.move`:

```move
module example_plugin::witness;

public struct Witness() has drop;

public(package) fun new(): Witness {
    Witness()
}
```

The vault validates this exact, non-generic `0xpkg::witness::Witness` shape
when authorizing it. The package-local constructor lets its own modules make a
witness while preventing downstream packages from doing so.

Move cannot express “`drop` and neither `copy` nor `store`,” nor can it prove
that a plugin has not exported another witness constructor. Those are required
offchain acceptance checks.

## Lifecycle

```move
let (vault, vault_admin_cap) = vault::new(composition_admin_cap, ctx);
vault.share();
```

- `new` wraps one capability and returns a vault-specific `VaultAdminCap`.
- `authorize_plugin` requires the admin cap and consumes the plugin witness.
- `borrow_as_plugin` consumes an authorized witness and returns `(Cap, Borrow)`.
- `borrow_as_admin` provides the same temporary lease to the admin cap holder.
- `put_back` returns the lease; it requires no further authorization because
  the hot potato itself proves the exact return.
- `revoke_plugin` requires only the admin cap, allowing unilateral revocation.
- `destroy` requires the matching admin cap and an empty Bag, then returns the
  exact custodied capability.

## Plugin usage

For a Miso Composition plugin, the plugin—not Vault—uses the full admin cap to
access the protocol’s extension surface:

```move
use miso::composition::{Composition, CompositionAdminCap};
use vault::vault::{Self, Vault};

entry fun execute<CompositionShare>(
    vault: &mut Vault<CompositionAdminCap<CompositionShare>>,
    composition: &mut Composition<CompositionShare>,
) {
    let (cap, receipt) = vault.borrow_as_plugin(witness::new());
    let uid = composition.uid_mut(&cap);
    // Perform this plugin's business operation with `uid`.
    vault.put_back(cap, receipt);
}
```

Installing a plugin delegates the full authority of `Cap` for the duration of
each successful lease. A plugin registry should disclose and score that
authority. Privileged plugin operations should generally be `entry fun`s so a
plugin cannot become a composable authority trampoline.

## Views

`id`, `VaultAdminCap::vault_id`, `authorized_plugins_id`,
`authorized_plugin_count`, and `is_plugin_authorized` are read-only. The Bag
itself is never returned.
