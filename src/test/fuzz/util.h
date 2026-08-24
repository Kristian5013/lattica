// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_TEST_FUZZ_UTIL_H
#define LATTICA_TEST_FUZZ_UTIL_H

#include <test/fuzz/fuzz.h>

#include <streams.h>
#include <uint256.h>
#include <util/check.h>

#include <fuzzer/FuzzedDataProvider.h>

#include <cstdint>
#include <span>
#include <vector>

/**
 * Helpers shared by the targets.
 *
 * FuzzedDataProvider is LLVM's, and takes a pointer and a length; a target is
 * handed a span. This is the seam between them, plus the few conversions every
 * target wants and none should write twice.
 */
inline FuzzedDataProvider MakeProvider(FuzzBufferType buffer)
{
    return FuzzedDataProvider{buffer.data(), buffer.size()};
}

//! A byte string of a length the fuzzer chose, up to `max`. LLVM's provider
//! offers this for strings and not for bytes, and a target that always consumed
//! a fixed count would never see a short key or an overlong signature.
inline std::vector<unsigned char> ConsumeRandomLengthBytes(FuzzedDataProvider& provider, size_t max)
{
    const size_t len = provider.ConsumeIntegralInRange<size_t>(0, max);
    return provider.ConsumeBytes<unsigned char>(len);
}

inline uint256 ConsumeUInt256(FuzzedDataProvider& provider)
{
    const std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(uint256::size());
    if (bytes.size() != uint256::size()) return uint256{};
    return uint256{bytes};
}

//! What is left of the buffer, as a stream a deserializer can read.
inline DataStream ConsumeStream(FuzzedDataProvider& provider)
{
    const std::vector<uint8_t> bytes = provider.ConsumeRemainingBytes<uint8_t>();
    return DataStream{bytes};
}

/**
 * Deserialize a T, and if that succeeded, check that writing it back gives the
 * same bytes.
 *
 * Round-tripping is the property worth asserting on a deserializer, because it
 * is the one an attacker can exploit when it fails: two encodings of the same
 * object mean two ids for the same transaction, and two ids mean a chain split.
 * A deserializer that throws is behaving; a deserializer that accepts bytes it
 * would not have written is not.
 */
template <typename T>
void DeserializeRoundTrip(DataStream& stream)
{
    const std::vector<std::byte> original{stream.begin(), stream.end()};
    T obj;
    try {
        stream >> obj;
    } catch (const std::ios_base::failure&) {
        return;
    }
    // Only the prefix that was consumed can be expected back.
    const size_t consumed = original.size() - stream.size();
    DataStream written;
    written << obj;
    if (written.size() != consumed) return; // a non-canonical encoding, not a memory fault
    Assert(std::equal(written.begin(), written.end(), original.begin()));
}

#endif // LATTICA_TEST_FUZZ_UTIL_H
