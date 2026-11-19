// Fuzzes cross-thread deallocation: rpmalloc_thread_initialize / rpmalloc_thread_finalize /
// rpmalloc_thread_collect with blocks allocated by one thread and reallocated or freed by another
// (deferred free lists, orphaned pages of exited threads, heap reuse by a new thread).
//
// Deterministic by construction: the op stream is split into phases and each phase is run by a
// fresh pthread that is joined before the next starts, so threads never run concurrently. They
// share one slot table, so blocks outlive the thread that allocated them. A phase thread ends
// with rpmalloc_thread_finalize or by just exiting (the thread-exit path), as the input chooses.
// Each input initializes and finalizes the allocator itself.
#include "rp_ops.h"

#include <pthread.h>

typedef struct {
	rp_table_t* table;
	rp_reader_t* reader;
	unsigned int ops;
	int finalize;
} phase_t;

static void*
phase_run(void* arg) {
	phase_t* ph = (phase_t*)arg;
	rpmalloc_thread_initialize();
	for (unsigned int i = 0; i < ph->ops && rp_more(ph->reader); ++i)
		rp_exec_op(ph->table, ph->reader, 0, -1);
	if (ph->finalize)
		rpmalloc_thread_finalize();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	rp_reader_t r = {data, size, 0};
	rp_table_t t;
	memset(&t, 0, sizeof(t));
	rp_init();
	for (unsigned int phase = 0; rp_more(&r) && phase < 16; ++phase) {
		uint8_t ctl = rp_u8(&r);
		phase_t ph = {&t, &r, 1 + (ctl >> 2) % 64, ctl & 1};
		if (ctl & 2) {
			// Run this phase on the main thread, freeing what earlier threads left behind
			for (unsigned int i = 0; i < ph.ops && rp_more(&r); ++i)
				rp_exec_op(&t, &r, 0, -1);
			rpmalloc_thread_collect();
			continue;
		}
		pthread_t thread;
		if (pthread_create(&thread, 0, phase_run, &ph) != 0)
			rp_fail("pthread_create failed", 0);
		pthread_join(thread, 0);
	}
	rp_free_all(&t, 0);
	rpmalloc_thread_collect();
	rpmalloc_finalize();
	return 0;
}
