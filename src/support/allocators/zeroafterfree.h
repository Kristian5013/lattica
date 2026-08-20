// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H
#define LATTICA_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H

#include <support/cleanse.h>

#include <memory>
#include <vector>

template <typename T>
struct zero_after_free_allocator {
    using value_type = T;

    zero_after_free_allocator() noexcept = default;
    template <typename U>
    zero_after_free_allocator(const zero_after_free_allocator<U>&) noexcept
    {
    }

    T* allocate(std::size_t n)
    {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T* p, std::size_t n)
    {
        if (p != nullptr)
            memory_cleanse(p, sizeof(T) * n);
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename U>
    friend bool operator==(const zero_after_free_allocator&, const zero_after_free_allocator<U>&) noexcept
    {
        return true;
    }
};

/** Byte-vector that clears its contents before deletion. */
using SerializeData = std::vector<std::byte, zero_after_free_allocator<std::byte>>;

#endif // LATTICA_SUPPORT_ALLOCATORS_ZEROAFTERFREE_H
