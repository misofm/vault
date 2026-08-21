# Vault

> Capability custody and plugin authorization for Miso `Composition`,
> `Recording`, and `Release` objects.

`Vault<Cap>` wraps one protocol admin capability and stores the canonical type
names of installed plugin witnesses. At creation it is permanently bound to
one target object ID. Every plugin package defines exactly one
`0xpkg::witness::Witness` type with only `drop`, constructed through a
package-only `witness::new()`. The vault never exposes the wrapped cap. Instead,
an installed plugin passes its witness by value to `composition_uid_mut`,
`recording_uid_mut`, or `release_uid_mut`. The vault consumes the witness,
verifies that its type is installed, and returns the corresponding protocol
object's `&mut UID`. The target ID is checked before the wrapped cap is used.

The vault package is designed to be immutable. Its `UpgradeCap` must be
consumed by `sui::package::make_immutable` when the package is published; there
is intentionally no application version or migration mechanism.

Read [SECURITY.md](./SECURITY.md) before placing a high-value capability in a
vault. In particular, installing an upgradable plugin trusts its entire package
upgrade lineage; a `TypeName` cannot pin execution to reviewed bytecode.

## Dependency

Pin the repository to a reviewed commit in consuming packages:

```toml
vault = { git = "https://github.com/misofm/vault.git", rev = "<commit>" }
```

## Plugin shape

`sources/witness.move`:

```move
module example_plugin::witness;

public struct Witness() has drop;

public(package) fun new(): Witness {
    Witness()
}
```

`sources/example_plugin.move`:

```move
module example_plugin::example_plugin;

use example_plugin::witness;
use miso::composition::{Composition, CompositionAdminCap};
use vault::vault::{Vault, VaultAdminCap};

entry fun install<CompositionShare>(
    vault: &mut Vault<CompositionAdminCap<CompositionShare>>,
    vault_admin_cap: &VaultAdminCap<CompositionAdminCap<CompositionShare>>,
) {
    vault.install_plugin(vault_admin_cap, witness::new())
}

entry fun execute<CompositionShare>(
    vault: &Vault<CompositionAdminCap<CompositionShare>>,
    composition: &mut Composition<CompositionShare>,
) {
    let uid = vault.composition_uid_mut(composition, witness::new());
    // Perform the plugin's bounded business operation with `uid`.
}
```

The constructor is available throughout the defining package but inaccessible
to downstream packages. The vault rejects primitives, generic types, and any
type whose path is not exactly `0xpkg::witness::Witness`. Move can require
`Witness: drop`, but cannot express a negative constraint such as “and not
`copy` or `store`,” so plugin packages must still declare `Witness` with exactly
the `drop` ability.

## Vault creation

The target object is required by reference so the vault can bind its authority
to that exact ID:

```move
let (vault, vault_admin_cap) = vault::new(
    &composition,
    composition_admin_cap,
    ctx,
);
vault.share();
```

## Entry functions

Authority-bearing plugin endpoints are good candidates for `entry fun`: this
prevents another Move package from calling the endpoint as an authority
trampoline. It is not required for every plugin function. Read-only functions
and deliberately composable operations may remain `public`, provided they
never return the witness, the wrapped cap, or the `&mut UID`.

## Lifecycle

- `new` binds the vault to a target object ID, wraps the admin cap, and returns
  a vault-specific `VaultAdminCap`.
- `share` shares the key-only vault through its defining module.
- `install_plugin` requires both the vault admin cap and the plugin witness.
- `uninstall_plugin` requires only the vault admin cap, so revocation never
  depends on cooperation from the plugin package.
- `destroy` requires every plugin to be uninstalled and returns the exact
  wrapped protocol admin cap.
