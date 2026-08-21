// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Ported from Bitcoin Core's src/script/descriptor.cpp, a piece at a time. This
// file so far holds the two parts that stand on their own and need no
// adaptation: the descriptor checksum, which is BIP380's and is defined over
// the string rather than over anything this chain hashes, and DescriptorCache.
//
// The Descriptor implementations and the parser follow. They do need adapting,
// and the shape of it is worth stating before the code arrives:
//
//   * Key expressions must admit three schemes. A secp256k1 key is 33 bytes and
//     has a WIF and an xpub; Falcon-512 and ML-DSA-44 keys are 897 and 1312 and
//     have neither.
//   * pqpkh(KEY) and pqsh(SCRIPT) are the witness v2 expressions.
//   * MaxSatSize cannot assume an ECDSA signature. Core's 71 or 72 bytes becomes
//     the scheme's own size, which for ML-DSA-44 is 2420, and fee estimation is
//     wrong by a factor of thirty if that is missed.
//   * A ranged expression over a lattice key cannot be public. Core's ranged
//     descriptors expand from an xpub without secrets, which is what makes a
//     watch-only wallet possible; a lattice public key has no homomorphism to
//     derive a child with, so such an expression must hold the xprv and there is
//     no public form of it to print.

#include <script/descriptor.h>

#include <pubkey.h>
#include <script/parsing.h>
#include <span.h>
#include <tinyformat.h>
#include <util/string.h>

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>

using util::Split;

namespace {

////////////////////////////////////////////////////////////////////////////
// Checksum                                                               //
////////////////////////////////////////////////////////////////////////////

// This section implements a checksum algorithm for descriptors with the
// following properties:
// * Mistakes in a descriptor string are measured in "symbol errors". The higher
//   the number of symbol errors, the harder it is to detect:
//   * An error substituting a character from 0123456789()[],'/*abcdefgh@:$%{} for
//     another in that set always counts as 1 symbol error.
//     * Note that hex encoded keys are covered by these characters. Xprvs and
//       xpubs use other characters too, but already have their own checksum
//       mechanism.
//     * Function names like "multi()" use other characters, but mistakes in
//       these would generally result in an unparsable descriptor.
//   * A case error always counts as 1 symbol error.
//   * Any other 1 character substitution error counts as 1 or 2 symbol errors.
// * Any 1 symbol error is always detected.
// * Any 2 or 3 symbol error in a descriptor of up to 49154 characters is always detected.
// * Any 4 symbol error in a descriptor of up to 507 characters is always detected.
// * Any 5 symbol error in a descriptor of up to 77 characters is always detected.
// * Is optimized to minimize the chance a 5 symbol error in a descriptor up to 387 characters is undetected
// * Random errors have a chance of 1 in 2**40 of being undetected.
//
// These properties are achieved by expanding every group of 3 (non checksum) characters into
// 4 GF(32) symbols, over which a cyclic code is defined.

/*
 * Interprets c as 8 groups of 5 bits which are the coefficients of a degree 8 polynomial over GF(32),
 * multiplies that polynomial by x, computes its remainder modulo a generator, and adds the constant term val.
 *
 * This generator is G(x) = x^8 + {30}x^7 + {23}x^6 + {15}x^5 + {14}x^4 + {10}x^3 + {6}x^2 + {12}x + {9}.
 * It is chosen to define an cyclic error detecting code which is selected by:
 * - Starting from all BCH codes over GF(32) of degree 8 and below, which by construction guarantee detecting
 *   3 errors in windows up to 19000 symbols.
 * - Taking all those generators, and for degree 7 ones, extend them to degree 8 by adding all degree-1 factors.
 * - Selecting just the set of generators that guarantee detecting 4 errors in a window of length 512.
 * - Selecting one of those with best worst-case behavior for 5 errors in windows of length up to 512.
 *
 * The generator and the constants to implement it can be verified using this Sage code:
 *   B = GF(2) # Binary field
 *   BP.<b> = B[] # Polynomials over the binary field
 *   F_mod = b**5 + b**3 + 1
 *   F.<f> = GF(32, modulus=F_mod, repr='int') # GF(32) definition
 *   FP.<x> = F[] # Polynomials over GF(32)
 *   E_mod = x**3 + x + F.fetch_int(8)
 *   E.<e> = F.extension(E_mod) # Extension field definition
 *   alpha = e**2743 # Choice of an element in extension field
 *   for p in divisors(E.order() - 1): # Verify alpha has order 32767.
 *       assert((alpha**p == 1) == (p % 32767 == 0))
 *   G = lcm([(alpha**i).minpoly() for i in [1056,1057,1058]] + [x + 1])
 *   print(G) # Print out the generator
 *   for i in [1,2,4,8,16]: # Print out {1,2,4,8,16}*(G mod x^8), packed in hex integers.
 *       v = 0
 *       for coef in reversed((F.fetch_int(i)*(G % x**8)).coefficients(sparse=True)):
 *           v = v*32 + coef.integer_representation()
 *       print("0x%x" % v)
 */
uint64_t PolyMod(uint64_t c, int val)
{
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffff) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989;
    if (c0 & 2) c ^= 0xa9fdca3312;
    if (c0 & 4) c ^= 0x1bab10e32d;
    if (c0 & 8) c ^= 0x3706b1677a;
    if (c0 & 16) c ^= 0x644d626ffd;
    return c;
}

std::string DescriptorChecksum(const std::span<const char>& span)
{
    /** A character set designed such that:
     *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
     *  - Case errors cause an offset that's a multiple of 32.
     *  - As many alphabetic characters are in the same group (while following the above restrictions).
     *
     * If p(x) gives the position of a character c in this character set, every group of 3 characters
     * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
     * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
     * affect a single symbol.
     *
     * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
     * the position within the groups.
     */
    static const std::string INPUT_CHARSET =
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

    /** The character set for the checksum itself (same as bech32). */
    static const std::string CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    uint64_t c = 1;
    int cls = 0;
    int clscount = 0;
    for (auto ch : span) {
        auto pos = INPUT_CHARSET.find(ch);
        if (pos == std::string::npos) return "";
        c = PolyMod(c, pos & 31); // Emit a symbol for the position inside the group, for every character.
        cls = cls * 3 + (pos >> 5); // Accumulate the group numbers
        if (++clscount == 3) {
            // Emit an extra symbol representing the group numbers, for every 3 characters.
            c = PolyMod(c, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if (clscount > 0) c = PolyMod(c, cls);
    for (int j = 0; j < 8; ++j) c = PolyMod(c, 0); // Shift further to determine the checksum.
    c ^= 1; // Prevent appending zeroes from not affecting the checksum.

    std::string ret(8, ' ');
    for (int j = 0; j < 8; ++j) ret[j] = CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31];
    return ret;
}

std::string AddChecksum(const std::string& str) { return str + "#" + DescriptorChecksum(str); }

bool CheckChecksum(std::span<const char>& sp, bool require_checksum, std::string& error, std::string* out_checksum = nullptr)
{
    auto check_split = Split(sp, '#');
    if (check_split.size() > 2) {
        error = "Multiple '#' symbols";
        return false;
    }
    if (check_split.size() == 1 && require_checksum){
        error = "Missing checksum";
        return false;
    }
    if (check_split.size() == 2) {
        if (check_split[1].size() != 8) {
            error = strprintf("Expected 8 character checksum, not %u characters", check_split[1].size());
            return false;
        }
    }
    auto checksum = DescriptorChecksum(check_split[0]);
    if (checksum.empty()) {
        error = "Invalid characters in payload";
        return false;
    }
    if (check_split.size() == 2) {
        if (!std::equal(checksum.begin(), checksum.end(), check_split[1].begin())) {
            error = strprintf("Provided checksum '%s' does not match computed checksum '%s'", std::string(check_split[1].begin(), check_split[1].end()), checksum);
            return false;
        }
    }
    if (out_checksum) *out_checksum = std::move(checksum);
    sp = check_split[0];
    return true;
}

} // namespace

////////////////////////////////////////////////////////////////////////////
// Public functions                                                       //
////////////////////////////////////////////////////////////////////////////

std::string GetDescriptorChecksum(const std::string& descriptor)
{
    std::string ret;
    std::string error;
    std::span<const char> sp{descriptor};
    if (!CheckChecksum(sp, false, error, &ret)) return "";
    return ret;
}

void DescriptorCache::CacheParentExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub)
{
    m_parent_xpubs[key_exp_pos] = xpub;
}

void DescriptorCache::CacheDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, const CExtPubKey& xpub)
{
    auto& xpubs = m_derived_xpubs[key_exp_pos];
    xpubs[der_index] = xpub;
}

void DescriptorCache::CacheLastHardenedExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub)
{
    m_last_hardened_xpubs[key_exp_pos] = xpub;
}

bool DescriptorCache::GetCachedParentExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const
{
    const auto& it = m_parent_xpubs.find(key_exp_pos);
    if (it == m_parent_xpubs.end()) return false;
    xpub = it->second;
    return true;
}

bool DescriptorCache::GetCachedDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, CExtPubKey& xpub) const
{
    const auto& key_exp_it = m_derived_xpubs.find(key_exp_pos);
    if (key_exp_it == m_derived_xpubs.end()) return false;
    const auto& der_it = key_exp_it->second.find(der_index);
    if (der_it == key_exp_it->second.end()) return false;
    xpub = der_it->second;
    return true;
}

bool DescriptorCache::GetCachedLastHardenedExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const
{
    const auto& it = m_last_hardened_xpubs.find(key_exp_pos);
    if (it == m_last_hardened_xpubs.end()) return false;
    xpub = it->second;
    return true;
}

DescriptorCache DescriptorCache::MergeAndDiff(const DescriptorCache& other)
{
    DescriptorCache diff;
    for (const auto& parent_xpub_pair : other.GetCachedParentExtPubKeys()) {
        CExtPubKey xpub;
        if (GetCachedParentExtPubKey(parent_xpub_pair.first, xpub)) {
            if (xpub != parent_xpub_pair.second) {
                throw std::runtime_error(std::string(__func__) + ": New cached parent xpub does not match already cached parent xpub");
            }
            continue;
        }
        CacheParentExtPubKey(parent_xpub_pair.first, parent_xpub_pair.second);
        diff.CacheParentExtPubKey(parent_xpub_pair.first, parent_xpub_pair.second);
    }
    for (const auto& derived_xpub_map_pair : other.GetCachedDerivedExtPubKeys()) {
        for (const auto& derived_xpub_pair : derived_xpub_map_pair.second) {
            CExtPubKey xpub;
            if (GetCachedDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, xpub)) {
                if (xpub != derived_xpub_pair.second) {
                    throw std::runtime_error(std::string(__func__) + ": New cached derived xpub does not match already cached derived xpub");
                }
                continue;
            }
            CacheDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, derived_xpub_pair.second);
            diff.CacheDerivedExtPubKey(derived_xpub_map_pair.first, derived_xpub_pair.first, derived_xpub_pair.second);
        }
    }
    for (const auto& lh_xpub_pair : other.GetCachedLastHardenedExtPubKeys()) {
        CExtPubKey xpub;
        if (GetCachedLastHardenedExtPubKey(lh_xpub_pair.first, xpub)) {
            if (xpub != lh_xpub_pair.second) {
                throw std::runtime_error(std::string(__func__) + ": New cached last hardened xpub does not match already cached last hardened xpub");
            }
            continue;
        }
        CacheLastHardenedExtPubKey(lh_xpub_pair.first, lh_xpub_pair.second);
        diff.CacheLastHardenedExtPubKey(lh_xpub_pair.first, lh_xpub_pair.second);
    }
    return diff;
}

ExtPubKeyMap DescriptorCache::GetCachedParentExtPubKeys() const
{
    return m_parent_xpubs;
}

std::unordered_map<uint32_t, ExtPubKeyMap> DescriptorCache::GetCachedDerivedExtPubKeys() const
{
    return m_derived_xpubs;
}

ExtPubKeyMap DescriptorCache::GetCachedLastHardenedExtPubKeys() const
{
    return m_last_hardened_xpubs;
}
