// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Test fixture for the canonical plugin witness package shape.
#[test_only]
module vault::witness;

/// The package's unique plugin installation identity.
public struct Witness() has drop;

/// A deliberately non-canonical datatype used to test witness validation.
public struct WrongName() has drop;

/// Construct the witness from any module in this package, but never from a
/// downstream package.
public(package) fun new(): Witness {
    Witness()
}

public(package) fun new_wrong_name(): WrongName {
    WrongName()
}
