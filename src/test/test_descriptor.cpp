// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Tests for what descriptor.cpp holds so far: BIP380's checksum and the cache
// of derived extended public keys.
//
// The checksum is defined over the descriptor string and has nothing to do with
// what this chain hashes, so it must agree with Bitcoin's exactly -- a wallet
// backup written by one and read by the other would otherwise be rejected. It
// is pinned against BIP380's own vector, which comes from the specification and
// not from this code.

#include <script/descriptor.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
bool Check(const char* name, bool ok)
{
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
    return ok;
}

} // namespace

int main()
{
    // ---- BIP380's vector. The specification gives raw(deadbeef) the checksum
    // 89f8spxm; anything else means the polynomial or the charset has drifted.
    {
        const std::string got = GetDescriptorChecksum("raw(deadbeef)");
        if (!Check("raw(deadbeef) has BIP380's checksum", got == "89f8spxm")) {
            std::printf("       got '%s', want '89f8spxm'\n", got.c_str());
        }
    }

    // ---- A descriptor that already carries its checksum keeps it.
    {
        Check("a correct checksum is returned unchanged",
              GetDescriptorChecksum("raw(deadbeef)#89f8spxm") == "89f8spxm");
        Check("a wrong checksum yields nothing",
              GetDescriptorChecksum("raw(deadbeef)#89f8spxn").empty());
        Check("a checksum of the wrong length yields nothing",
              GetDescriptorChecksum("raw(deadbeef)#89f8spx").empty());
        Check("two '#' yield nothing",
              GetDescriptorChecksum("raw(deadbeef)#89f8spxm#89f8spxm").empty());
    }

    // ---- Characters outside the input charset have no checksum at all, which
    // is what stops a descriptor with a stray byte from being silently accepted.
    {
        Check("a character outside the charset yields nothing",
              GetDescriptorChecksum(std::string("raw(deadbeef)") + '\x01').empty());
    }

    // ---- The property the algorithm exists for: every single-character change
    // in the payload changes the checksum. Walk one position through the whole
    // input charset and confirm no collision.
    {
        const std::string base = "raw(deadbeef)";
        const std::string want = GetDescriptorChecksum(base);
        const std::string charset =
            "0123456789()[],'/*abcdefgh@:$%{}"
            "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
            "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
        int collisions = 0, tried = 0;
        for (char c : charset) {
            if (c == '#') continue; // would be read as the checksum separator
            std::string mutated = base;
            mutated[6] = c;
            if (mutated == base) continue;
            ++tried;
            if (GetDescriptorChecksum(mutated) == want) ++collisions;
        }
        Check("a one-character change always changes the checksum", tried > 80 && collisions == 0);
    }

    // ---- The cache, whose whole job is to let a ranged descriptor expand
    // without private keys. It is empty for the lattice schemes by construction:
    // there is no extended public key to put in it.
    {
        DescriptorCache cache;
        CExtPubKey xpub;
        Check("an empty cache has no parent", !cache.GetCachedParentExtPubKey(0, xpub));
        Check("nor a derived key", !cache.GetCachedDerivedExtPubKey(0, 0, xpub));
        Check("nor a last hardened one", !cache.GetCachedLastHardenedExtPubKey(0, xpub));

        CExtPubKey a;
        a.nDepth = 1;
        a.nChild = 7;
        cache.CacheParentExtPubKey(0, a);
        CExtPubKey back;
        Check("a cached parent comes back", cache.GetCachedParentExtPubKey(0, back) && back == a);
        Check("...and only under its own index", !cache.GetCachedParentExtPubKey(1, back));

        cache.CacheDerivedExtPubKey(0, 5, a);
        Check("a derived key comes back at its index", cache.GetCachedDerivedExtPubKey(0, 5, back) && back == a);
        Check("...and not at another", !cache.GetCachedDerivedExtPubKey(0, 6, back));
    }

    // ---- MergeAndDiff returns what the other cache knew and this one did not,
    // and refuses a contradiction rather than overwriting.
    {
        DescriptorCache mine, theirs;
        CExtPubKey a, b;
        a.nDepth = 1;
        b.nDepth = 2;
        mine.CacheParentExtPubKey(0, a);
        theirs.CacheParentExtPubKey(0, a);
        theirs.CacheParentExtPubKey(1, b);

        const DescriptorCache diff = mine.MergeAndDiff(theirs);
        CExtPubKey got;
        Check("the diff holds only what was new", !diff.GetCachedParentExtPubKey(0, got) &&
              diff.GetCachedParentExtPubKey(1, got) && got == b);
        Check("and the merge took it", mine.GetCachedParentExtPubKey(1, got) && got == b);

        DescriptorCache conflicting;
        conflicting.CacheParentExtPubKey(0, b); // same index, different key
        bool threw = false;
        try {
            mine.MergeAndDiff(conflicting);
        } catch (const std::runtime_error&) {
            threw = true;
        }
        Check("a contradicting cache is refused, not merged", threw);
    }

    std::printf("%s\n", g_fail == 0 ? "ALL PASS" : "FAILURES");
    return g_fail == 0 ? 0 : 1;
}
