// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <bench/bench.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/check.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>

static void FindByte(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const BasicTestingSetup>(ChainType::REGTEST)};
    AutoFile file{fsbridge::fopen(testing_setup->m_path_root / "streams_tmp", "w+b")};
    const size_t file_size = 200;
    uint8_t data[file_size] = {0};
    data[file_size - 1] = 1;
    file << data;
    file.seek(0, SEEK_SET);
    BufferedFile bf{file, /*nBufSize=*/file_size + 1, /*nRewindIn=*/file_size};

    bench.setup([&] { bf.SetPos(0); })
        .run([&] { bf.FindByte(std::byte(1)); });

    assert(file.fclose() == 0);
}

BENCHMARK(FindByte);
