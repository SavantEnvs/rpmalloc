// Fuzzes the global rpmalloc API (thread heap): rpmalloc, rpzalloc, rpcalloc, rprealloc,
// rpaligned_alloc/zalloc/calloc/realloc, rpmemalign, rpposix_memalign, rpmalloc_usable_size,
// rpfree, rpmalloc_thread_collect. The fuzz input is an op stream (see rp_ops.h).
//
// Each input starts from a freshly initialized allocator and ends with every block freed and the
// allocator finalized, so its result depends only on that input.
#include "rp_ops.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	rp_reader_t r = {data, size, 0};
	rp_table_t t;
	memset(&t, 0, sizeof(t));
	rp_init();
	for (unsigned int ops = 0; rp_more(&r) && ops < 4096; ++ops)
		rp_exec_op(&t, &r, 0, -1);
	rp_free_all(&t, 0);
	rpmalloc_finalize();
	return 0;
}
