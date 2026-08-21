# Security Model

`Vault` can custody capabilities controlling high-value protocol objects. Its
small API is intentional. This document defines what the package guarantees
and which risks remain outside the onchain primitive.

## Enforced onchain

- The wrapped admin capability is a private field. No public API returns it or
  a reference to it.
- `Vault` has `key` but not `store`, so downstream packages cannot publicly
  transfer, wrap, freeze, or share it. The defining module controls sharing and
  destruction.
- `VaultAdminCap<Cap>` is unforgeable and bound to one vault ID. It is required
  to install or uninstall plugins and to destroy the vault.
- A vault is permanently bound to the target object ID supplied to `new`.
  Every `*_uid_mut` function rejects a different target before using the
  wrapped cap.
- Every `*_uid_mut` function requires an installed witness type and consumes
  the witness by value before returning `&mut UID` to the calling Move code.
- Vault state is versioned. Security-sensitive functions reject a vault state
  version they do not understand, allowing a future migration to decommission
  old package code for migrated vaults.
- The vault cannot be destroyed while any plugin remains installed. Destruction
  requires the matching `VaultAdminCap` and returns the exact wrapped cap.

The three mutable-UID paths are `composition_uid_mut`, `recording_uid_mut`, and
`release_uid_mut`. Each performs the same version, witness, and target checks.
The protocol's `release::uid_mut` additionally verifies the release ID embedded
in `ReleaseAdminCap`. Composition and Recording authorization also relies on
the protocol invariant that their share type uniquely identifies the object.

## Root authorities

Treat each of these as full authority over the protected object:

1. **`VaultAdminCap`.** Its holder can install arbitrary plugin witnesses,
   revoke plugins, or destroy the empty vault and recover the wrapped cap.
2. **The vault package `UpgradeCap`.** A compatible upgrade can change function
   implementations or add new functions with access to private vault fields.
   For high-value production deployment, make the package immutable or place
   the `UpgradeCap` behind independently reviewed multisig/timelock governance.
3. **Every installed plugin package and its `UpgradeCap`.** An installed plugin
   receives root access to every dynamic field under the target UID. A malicious
   plugin can mutate or remove another extension's fields when their keys are
   constructible.
4. **The pinned Miso protocol package.** The vault ultimately calls the
   protocol's cap-gated UID accessors.

Vault state versioning helps retire old code after a legitimate upgrade. It
does not protect against a malicious holder of the vault package `UpgradeCap`,
because upgraded code can omit the version check.

## Plugin upgrade identity

The vault stores `type_name::with_defining_ids<Witness>()`. The defining ID is
the package version that first introduced `Witness`; it is not the version of
the code currently executing. The witness retains that identity through later
package upgrades. Consequently, no `std::type_name` function can restrict an
installation to the plugin's initial bytecode version.

An immutable plugin package provides the strongest code guarantee. If a plugin
is upgradable, clients must evaluate the owner and policy of its `UpgradeCap`
and clearly disclose that installing it trusts future compatible code.

## Witness limitations

The required plugin witness is:

```move
module example_plugin::witness;

public struct Witness() has drop;

public(package) fun new(): Witness {
    Witness()
}
```

The compiler prevents downstream packages from packing `Witness` or calling
the package-only constructor. The vault additionally rejects primitives,
generic types, and any type whose module and datatype are not exactly
`witness::Witness`. Move can require `Witness: drop`, but it cannot express
“drop and neither copy nor store.” The vault therefore cannot enforce the exact
ability set or prevent a plugin package from exporting its witness. Those
properties must be checked from verified source and bytecode before
installation.

Authority-bearing plugin endpoints should be `entry fun` and must never return
the witness or `&mut UID`. A Move call in a PTB cannot return a reference, so
the UID reference remains inside the calling Move function, but a composable
plugin function can still act as an authority trampoline for other packages.

## Client-side acceptance policy

Plugin safety is an offchain policy decision. A client or registry should
reject a plugin unless it can verify:

- deployed bytecode matches published source;
- the witness has exactly `drop`, a package-only constructor, and no public
  export path;
- every privileged operation is bounded, does not leak authority, and requests
  only the object classes it needs;
- all dependencies and their upgrade authorities are identified;
- the plugin's `UpgradeCap` status, owner, and policy are disclosed;
- audits, tests, known incidents, and the reviewed source commit are recorded.

Miso's plugin registry maintains the detailed scoring proposal. Immutability
should carry the largest weight, and unsafe witness construction should be a
hard rejection rather than a low score.

## Operational guidance

- Custody `VaultAdminCap` with security at least as strong as the wrapped cap;
  use multisig governance for high-value objects.
- Review every plugin and its transitive dependencies before installation.
- Re-evaluate scores and upgrade authorities continuously, not only at install.
- Uninstall a plugin before a known-risk upgrade or incident.
- Do not send unrelated objects to the vault or admin-cap object IDs; deleting
  those parent objects can strand objects owned by their addresses.
