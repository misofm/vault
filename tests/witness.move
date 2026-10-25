// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: FSL-1.1-ALv2

#[test_only]
module vault::witness;

public struct Witness() has drop;

public(package) fun new(): Witness {
    Witness()
}
