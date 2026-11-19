// Fuzzes allocator initialization with a fuzzed configuration and custom memory interface:
// rpmalloc_initialize_config(interface, config), rpmalloc_config, the statistics API
// (built with ENABLE_STATISTICS=1) and rpmalloc_finalize with unmap_on_finalize.
//
// The first input bytes pick the config (page_size, enable_thp, disable_thp, disable_decommit,
// unmap_on_finalize, page names) and whether to install an mmap-backed memory interface that
// fails the Nth map or commit call. Then an op stream as in fuzz_alloc runs (NULL results are
// tolerated once failures are injected), statistics are read, all blocks are freed and the
// allocator is finalized. With unmap_on_finalize the custom interface must see every mapping
// returned. Each input initializes and finalizes the allocator itself; the process-wide THP
// disable flag a config can set is cleared again after finalize so the next input starts clean.
#include "rp_ops.h"

#include <sys/mman.h>
#include <sys/prctl.h>

static long map_calls, commit_calls, fail_map_at, fail_commit_at;
static long live_mappings;
static size_t live_mapped_bytes;
static FILE* devnull;

static void*
fz_map(size_t size, size_t alignment, size_t* offset, size_t* mapped_size) {
	if (fail_map_at && ++map_calls == fail_map_at)
		return 0;
	size_t total = size + alignment;
	uint8_t* raw = (uint8_t*)mmap(0, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED)
		return 0;
	uint8_t* ptr = raw;
	if (alignment) {
		uintptr_t mask = (uintptr_t)alignment - 1;
		ptr = (uint8_t*)(((uintptr_t)raw + mask) & ~mask);
	}
	*offset = (size_t)(ptr - raw);
	*mapped_size = total;
	++live_mappings;
	live_mapped_bytes += total;
	return ptr;
}

static void
fz_unmap(void* address, size_t offset, size_t mapped_size) {
	if (munmap((uint8_t*)address - offset, mapped_size) != 0) {
		fprintf(stderr, "munmap of a range the allocator did not get from memory_map\n");
		abort();
	}
	--live_mappings;
	live_mapped_bytes -= mapped_size;
}

static int
fz_commit(void* address, size_t size) {
	(void)address;
	(void)size;
	if (fail_commit_at && ++commit_calls == fail_commit_at)
		return 1;
	return 0;
}

static int
fz_decommit(void* address, size_t size) {
	// The interface contract lets decommitted pages keep their content
	(void)address;
	(void)size;
	return 0;
}

static int
fz_map_fail(size_t size) {
	(void)size;
	return 0;
}

int
LLVMFuzzerInitialize(int* argc, char*** argv) {
	(void)argc;
	(void)argv;
	devnull = fopen("/dev/null", "w");
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	static const size_t page_sizes[] = {0, 4096, 16384, 65536};
	rp_reader_t r = {data, size, 0};
	rp_table_t t;
	memset(&t, 0, sizeof(t));

	uint8_t c0 = rp_u8(&r), c1 = rp_u8(&r);
	rpmalloc_config_t config;
	memset(&config, 0, sizeof(config));
	config.page_size = page_sizes[c0 & 3];
	config.enable_thp = (c0 >> 2) & 1;
	config.disable_decommit = (c0 >> 3) & 1;
	// Always on: without it finalize keeps the mappings and every input would leak address space.
	config.unmap_on_finalize = 1;
	config.disable_thp = (c0 >> 5) & 1;
	config.page_name = (c0 >> 6) & 1 ? "rpmalloc-fuzz" : 0;
	config.huge_page_name = (c0 >> 7) & 1 ? "rpmalloc-fuzz-huge" : 0;

	rpmalloc_interface_t iface;
	memset(&iface, 0, sizeof(iface));
	int custom = c1 & 1;
	map_calls = commit_calls = 0;
	fail_map_at = fail_commit_at = 0;
	live_mappings = 0;
	live_mapped_bytes = 0;
	if (custom) {
		iface.memory_map = fz_map;
		iface.memory_unmap = fz_unmap;
		iface.memory_commit = fz_commit;
		iface.memory_decommit = fz_decommit;
		if (c1 & 2)
			fail_map_at = 2 + rp_u8(&r) % 64;
		if (c1 & 4)
			fail_commit_at = 2 + rp_u8(&r) % 64;
	} else {
		iface.map_fail_callback = fz_map_fail;
	}
	rp_tolerate_null = (fail_map_at || fail_commit_at);

	if (rpmalloc_initialize_config(&iface, &config) != 0) {
		if (!rp_tolerate_null)
			rp_fail("rpmalloc_initialize_config failed", 0);
		rp_tolerate_null = 0;
		return 0;
	}
	const rpmalloc_config_t* active = rpmalloc_config();
	if (!active || (config.page_size && active->page_size && (active->page_size & (active->page_size - 1))))
		rp_fail("rpmalloc_config reports an invalid page size", 0);

	for (unsigned int ops = 0; rp_more(&r) && ops < 2048; ++ops) {
		if ((rp_u8(&r) % 16) == 0) {
			rpmalloc_thread_statistics_t ts;
			rpmalloc_global_statistics_t gs;
			rpmalloc_thread_statistics(&ts);
			rpmalloc_global_statistics(&gs);
			if (gs.mapped_peak < gs.mapped || gs.active_peak < gs.active || gs.huge_alloc_peak < gs.huge_alloc)
				rp_fail("statistics peak below current value", 0);
			continue;
		}
		rp_exec_op(&t, &r, 0, -1);
	}
	rpmalloc_dump_statistics(devnull);
	rp_free_all(&t, 0);
	int unmap_all = active->unmap_on_finalize;
	rpmalloc_finalize();
	if (custom && unmap_all && live_mappings) {
		fprintf(stderr, "%ld mappings (%zu bytes) left after finalize with unmap_on_finalize\n", live_mappings,
		        live_mapped_bytes);
		abort();
	}
	if (config.disable_thp)
		(void)prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0);
	rp_tolerate_null = 0;
	return 0;
}
