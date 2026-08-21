// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Test fixture for the canonical plugin witness package shape.
#[test_only]
module vault::witness;

/// The package's unique plugin installation identity.
public struct Witness() has drop;

/// Construct the witness from any module in this package, but never from a
/// downstream package.
public(package) fun new(): Witness {
    Witness()
}
