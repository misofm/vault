// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module vault::witness;

public struct Witness() has drop;

public(package) fun new(): Witness {
    Witness()
}
