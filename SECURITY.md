# Security Model

`Vault` can custody high-value capabilities. It is deliberately generic: it
does not know what a `Cap` authorizes. Vault owners must therefore treat an
authorized plugin as a delegate of the full custodied capability.

## Enforced onchain

- `cap` is a private `sui::borrow::Referent<Cap>` field. No API exposes the
  Referent or the Bag.
- `borrow_as_plugin` consumes a witness and checks its private typed
  `AuthorizedPluginKey<Witness>` record in the Bag.
- `borrow_as_admin`, authorization, revocation, and destruction check a
  vault-specific, unforgeable `VaultAdminCap`.
- `Referent` returns `Cap` with a no-ability `Borrow` receipt. Sui verifies
  the returned cap has the original object ID and returns to the originating
  referent. An unfinished or substituted lease aborts atomically.
- `Bag` tracks authorization records and can be destroyed only when empty.
  Consequently, `destroy` cannot leave inaccessible authorization fields.
- `Vault` has `key` but not `store`; only the defining module can share or
  destroy it. `VaultAdminCap` has private fields and is bound to its vault ID.

`put_back` intentionally requires no administrator or plugin authorization.
The hot-potato receipt itself is the authority to return the borrowed cap;
adding a gate could strand the cap and create a liveness failure.

## Root authorities

1. **The holder of `VaultAdminCap`.** It can authorize arbitrary plugin
   witness types, revoke authorization, borrow the cap directly, or destroy an
   empty vault and recover the cap.
2. **Every authorized plugin package and its upgrade authority.** It can lease
   the entire `Cap`, invoke every public operation that cap permits, and pass
   it to other code during its transaction endpoint.
3. **The custodied capability's defining package and its upgrade authority.**
   Vault cannot strengthen the authorization rules implemented by `Cap`.
4. **The Vault package `UpgradeCap` until immutability is finalized.**

Use multisig or equivalent governance for high-value `VaultAdminCap`s and
upgrade authorities.

## Deployment immutability

Vault is designed to have no upgrades. In the same publication transaction,
consume its `UpgradeCap` with `sui::package::make_immutable`, then verify the
cap's deletion onchain before depositing a valuable capability. Until then, an
upgrade authority can alter Vault's private authorization logic.

Plugins should preferably also be immutable. If a plugin is upgradable, an
authorization trusts its complete compatible-upgrade lineage. Sui
`type_name::with_defining_ids<Witness>()` identifies the package version that
first introduced the type; it does not pin the bytecode currently executing.

## Witness checks and their limits

`authorize_plugin` requires a `drop` witness whose type is exactly a
non-generic `0xpkg::witness::Witness`. This prevents primitive, generic, and
wrong-path types from being authorized.

The check cannot prove that Witness has only `drop`, that its constructor is
package-only, or that the package has not exported another construction path.
The Move compiler protects a properly written package-only constructor, but
clients must verify the exact witness definition and all exported functions
offchain before authorizing a plugin.

## Plugin endpoint policy

Use `entry fun` for authority-bearing plugin endpoints whenever the plugin
should not serve as a downstream Move authority trampoline. A plugin must not
return the leased `Cap`, `Borrow`, a witness, or a privileged mutable reference.
The lease and return should occur inside one plugin function.

## Offchain acceptance policy

Plugin safety is a client or registry decision. A plugin should be rejected
unless the reviewer can verify:

- source matches deployed bytecode and the reviewed commit;
- `witness::Witness` has exactly `drop`, its intended constructor is
  `public(package)`, and no public construction path exists;
- the plugin's full-capability operations are narrowly understood and every
  dependency and upgrade authority is identified;
- the plugin package's immutability, upgrade policy, owner, audits, tests, and
  incidents are disclosed; and
- its transaction endpoints do not leak capability authority or act as an
  unintended public trampoline.

Immutability should be the largest factor in the corresponding plugin safety
score. It is not an onchain substitute for source and bytecode review.
