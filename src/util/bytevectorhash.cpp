// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <util/bytevectorhash.h>

#include <crypto/siphash.h>
#include <random.h>

#include <span>
#include <vector>

ByteVectorHash::ByteVectorHash() :
    m_k0(FastRandomContext().rand64()),
    m_k1(FastRandomContext().rand64())
{
}

size_t ByteVectorHash::operator()(const std::vector<unsigned char>& input) const
{
    return CSipHasher(m_k0, m_k1).Write(input).Finalize();
}