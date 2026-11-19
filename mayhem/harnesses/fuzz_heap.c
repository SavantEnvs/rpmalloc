// Fuzzes the first-class heap API (RPMALLOC_FIRST_CLASS_HEAPS=1): rpmalloc_heap_acquire/_release,
// _alloc, _aligned_alloc/_zalloc, _calloc/_aligned_calloc, _realloc/_aligned_realloc, _free,
// _free_all and rpmalloc_get_heap_for_ptr, interleaved with the global thread-heap API.
//
// Up to 4 heaps live at once; every block in the slot table is tagged with its owning heap and is
// only ever reallocated/freed through that heap (the API contract). Each input starts from a freshly
// initialized allocator and ends with every heap emptied and released and the allocator finalized.
#include "rp_ops.h"

#define RP_HEAPS 4

static void
heap_drop_slots(rp_table_t* t, int owner) {
	for (int i = 0; i < RP_SLOTS; ++i) {
		if (t->slot[i].ptr && t->slot[i].owner == owner)
			rp_release_slot(t, &t->slot[i]);
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	rp_reader_t r = {data, size, 0};
	rp_table_t t;
	rpmalloc_heap_t* heaps[RP_HEAPS] = {0};
	memset(&t, 0, sizeof(t));
	rp_init();
	for (unsigned int ops = 0; rp_more(&r) && ops < 4096; ++ops) {
		uint8_t ctl = rp_u8(&r);
		int h = ctl % RP_HEAPS;
		switch ((ctl >> 2) % 8) {
		case 0:  // acquire a heap
			if (!heaps[h])
				heaps[h] = rpmalloc_heap_acquire();
			if (!heaps[h])
				rp_fail("heap acquire failed", 0);
			break;
		case 1:  // free_all + release
		case 2:  // free_all, keep the heap
			if (!heaps[h])
				break;
			for (int i = 0; i < RP_SLOTS; ++i) {
				if (t.slot[i].ptr && t.slot[i].owner == h)
					rp_verify(&t.slot[i]);
			}
			rpmalloc_heap_free_all(heaps[h]);
			heap_drop_slots(&t, h);
			if (((ctl >> 2) % 8) == 1) {
				rpmalloc_heap_release(heaps[h]);
				heaps[h] = 0;
			}
			break;
		case 3: {  // ownership query on a live block
			rp_slot_t* s = &t.slot[rp_u8(&r) % RP_SLOTS];
			if (s->ptr && s->owner >= 0 && rpmalloc_get_heap_for_ptr(s->ptr) != heaps[s->owner])
				rp_fail("rpmalloc_get_heap_for_ptr does not return the owning heap", s);
			break;
		}
		case 4:  // global API op
			rp_exec_op(&t, &r, heaps, -1);
			break;
		default:  // op on heap h
			if (!heaps[h])
				heaps[h] = rpmalloc_heap_acquire();
			{
				// A slot owned by another heap is freed through its owner before reuse; realloc of
				// a block owned by another heap is not allowed, so it is skipped.
				size_t save = r.pos;
				(void)rp_u8(&r);
				rp_slot_t* s = &t.slot[rp_u8(&r) % RP_SLOTS];
				r.pos = save;
				if (s->ptr && s->owner != h)
					rp_free_slot(&t, s, heaps);
			}
			rp_exec_op(&t, &r, heaps, h);
			break;
		}
	}
	rp_free_all(&t, heaps);
	for (int h = 0; h < RP_HEAPS; ++h) {
		if (heaps[h]) {
			rpmalloc_heap_free_all(heaps[h]);
			rpmalloc_heap_release(heaps[h]);
		}
	}
	rpmalloc_finalize();
	return 0;
}
