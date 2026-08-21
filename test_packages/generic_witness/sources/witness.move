// Copyright (c) Miso Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// An intentionally invalid generic witness used only by vault tests.
module generic_witness::witness;

public struct Witness<phantom T>() has drop;

public fun new<T>(): Witness<T> {
    Witness()
}
