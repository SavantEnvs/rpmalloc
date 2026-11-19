// Shared op-stream engine for the rpmalloc fuzz harnesses.
//
// rpmalloc has no parser: its untrusted input is the sequence and the arguments of allocation calls
// (sizes, counts, alignments, realloc flags, free order). Each harness decodes the fuzz bytes into a
// stream of such calls over a table of live blocks and self-checks every result, because rpmalloc
// maps its own memory and ASan sees no redzones inside rpmalloc blocks:
//   - every live block carries a fill pattern over its whole requested size, verified before every
//     realloc and free (catches overlapping blocks / blocks handed out twice / bad realloc copies),
//   - zeroed allocations (zalloc/calloc) read as zero over the requested size,
//   - the returned pointer honours the requested alignment,
//   - rpmalloc_usable_size(p) >= requested size,
//   - an overflowing num*size in a calloc returns NULL.
// A failed check calls abort() with a message on stderr.
#ifndef RP_OPS_H
#define RP_OPS_H

#include <rpmalloc.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RP_SLOTS 64
#define RP_MAX_BLOCK ((size_t)16 * 1024 * 1024)
#define RP_MAX_LIVE ((size_t)192 * 1024 * 1024)

typedef struct {
	const uint8_t* data;
	size_t size;
	size_t pos;
} rp_reader_t;

static inline int
rp_more(rp_reader_t* r) {
	return r->pos < r->size;
}

static inline uint8_t
rp_u8(rp_reader_t* r) {
	return (r->pos < r->size) ? r->data[r->pos++] : 0;
}

static inline uint32_t
rp_u16(rp_reader_t* r) {
	uint32_t lo = rp_u8(r);
	return lo | ((uint32_t)rp_u8(r) << 8);
}

static inline uint32_t
rp_u32(rp_reader_t* r) {
	uint32_t lo = rp_u16(r);
	return lo | (rp_u16(r) << 16);
}

// A size drawn from buckets that cover every size class range of rpmalloc: small (<= 4KiB),
// medium (<= 256KiB), large (<= 2MiB) and huge (> 2MiB, capped at RP_MAX_BLOCK), plus values
// right around the class limits.
static inline size_t
rp_size(rp_reader_t* r) {
	static const size_t edges[] = {0, 1, 8, 16, 1024, 4096, 8192, 65536, 262144, 2097152, 4194304, 8388608};
	uint8_t sel = rp_u8(r);
	uint32_t v = rp_u32(r);
	switch (sel & 7) {
	case 0: return v % 129;
	case 1: return v % 1025;
	case 2: return v % 4097;
	case 3: return v % 65537;
	case 4: return v % 262145;
	case 5: return v % 2097153;
	case 6: return 2097152 + (v % (RP_MAX_BLOCK - 2097152 + 1));
	default: {
		size_t base = edges[(sel >> 3) % (sizeof(edges) / sizeof(edges[0]))];
		int delta = (int)(v % 33) - 16;
		if (delta < 0 && (size_t)(-delta) > base)
			return 0;
		return base + (size_t)(ptrdiff_t)delta;
	}
	}
}

// An alignment as the API requires it: a power of two, multiple of sizeof(void*), from 8 up to and
// including RPMALLOC_MAX_ALIGNMENT (256KiB), which rpmalloc rejects with EINVAL (NULL result).
static inline size_t
rp_align(rp_reader_t* r) {
	unsigned int shift = 3 + (rp_u8(r) % 16);  // 8 .. 256KiB
	return (size_t)1 << shift;
}

// Set by a harness whose memory interface fails mappings on purpose: a NULL result is then the
// expected out-of-memory answer rather than an allocator bug.
static int rp_tolerate_null;

typedef struct {
	uint8_t* ptr;
	size_t size;
	size_t align;
	uint8_t pattern;
	int owner;  // heap index for first-class heap harnesses, -1 for the thread heap
} rp_slot_t;

typedef struct {
	rp_slot_t slot[RP_SLOTS];
	size_t live;
	uint8_t next_pattern;
} rp_table_t;

static inline void
rp_fail(const char* what, const rp_slot_t* s) {
	fprintf(stderr, "rpmalloc self-check failed: %s (ptr=%p size=%zu align=%zu)\n", what, (void*)(s ? s->ptr : 0),
	        s ? s->size : 0, s ? s->align : 0);
	abort();
}

static inline void
rp_check_zero(const rp_slot_t* s) {
	for (size_t i = 0; i < s->size; ++i) {
		if (s->ptr[i])
			rp_fail("zeroed allocation is not zero", s);
	}
}

static inline void
rp_fill(rp_slot_t* s) {
	if (s->size)
		memset(s->ptr, s->pattern, s->size);
}

static inline void
rp_verify_prefix(const rp_slot_t* s, size_t len, uint8_t pattern) {
	for (size_t i = 0; i < len; ++i) {
		if (s->ptr[i] != pattern)
			rp_fail("block content corrupted", s);
	}
}

static inline void
rp_verify(const rp_slot_t* s) {
	rp_verify_prefix(s, s->size, s->pattern);
}

// Checks a freshly returned block and makes it the content of slot s.
static inline void
rp_adopt(rp_table_t* t, rp_slot_t* s, void* p, size_t size, size_t align, int zeroed, int owner) {
	s->ptr = (uint8_t*)p;
	s->size = size;
	s->align = align;
	s->owner = owner;
	if (align && ((uintptr_t)p % align))
		rp_fail("block is not aligned", s);
	if (rpmalloc_usable_size(p) < size)
		rp_fail("usable size below the requested size", s);
	if (zeroed)
		rp_check_zero(s);
	s->pattern = (uint8_t)(++t->next_pattern | 1);
	rp_fill(s);
	t->live += size;
}

// Initializes the allocator for one input. unmap_on_finalize makes rpmalloc_finalize() return every
// mapping, so the per-input init/finalize cycle does not leak address space from input to input.
static inline void
rp_init(void) {
	rpmalloc_config_t config;
	memset(&config, 0, sizeof(config));
	config.unmap_on_finalize = 1;
	if (rpmalloc_initialize_config(0, &config) != 0)
		rp_fail("rpmalloc_initialize_config failed", 0);
}

static inline int
rp_room(const rp_table_t* t, size_t size) {
	return size <= RP_MAX_BLOCK && t->live + size <= RP_MAX_LIVE;
}

static inline int
rp_mul_overflows(size_t a, size_t b) {
	size_t r;
	return __builtin_mul_overflow(a, b, &r);
}

// A num/size pair for calloc: either a product within the block cap, or an overflowing one.
static inline void
rp_calloc_args(rp_reader_t* r, size_t* num, size_t* size) {
	uint8_t sel = rp_u8(r);
	if ((sel & 7) == 7) {
		// Products that overflow size_t (06b18dd: calloc/heap_calloc/aligned_calloc overflow checks)
		*num = ((size_t)1 << (32 + (sel >> 3) % 32)) + rp_u16(r);
		*size = ((size_t)1 << (32 + rp_u8(r) % 32)) + rp_u16(r);
		return;
	}
	*size = rp_u16(r) % 4097;
	size_t total = rp_size(r);
	*num = (*size) ? (total / *size) : (size_t)rp_u16(r);
}

static inline void
rp_release_slot(rp_table_t* t, rp_slot_t* s) {
	t->live -= s->size;
	s->ptr = 0;
	s->size = 0;
}

// Frees the block in slot s (after verifying its content) through the API that owns it.
static inline void
rp_free_slot(rp_table_t* t, rp_slot_t* s, rpmalloc_heap_t** heaps) {
	if (!s->ptr)
		return;
	rp_verify(s);
#if RPMALLOC_FIRST_CLASS_HEAPS
	if (s->owner >= 0)
		rpmalloc_heap_free(heaps[s->owner], s->ptr);
	else
#endif
		rpfree(s->ptr);
	(void)heaps;
	rp_release_slot(t, s);
}

static inline void
rp_free_all(rp_table_t* t, rpmalloc_heap_t** heaps) {
	for (int i = 0; i < RP_SLOTS; ++i)
		rp_free_slot(t, &t->slot[i], heaps);
}

// Runs one allocation op decoded from r on table t. With heap != NULL (owner = its index in heaps)
// the op goes through the first-class heap API, otherwise through the global thread-heap API.
static inline void
rp_exec_op(rp_table_t* t, rp_reader_t* r, rpmalloc_heap_t** heaps, int owner) {
	uint8_t op = rp_u8(r);
	rp_slot_t* s = &t->slot[rp_u8(r) % RP_SLOTS];
#if RPMALLOC_FIRST_CLASS_HEAPS
	rpmalloc_heap_t* heap = (owner >= 0) ? heaps[owner] : 0;
#else
	void* heap = 0;
#endif
	void* p = 0;
	size_t size = 0, num = 0, align = 0;
	switch (op % 12) {
	case 0:  // malloc
	case 1:  // zalloc
		size = rp_size(r);
		rp_free_slot(t, s, heaps);
		if (!rp_room(t, size))
			return;
#if RPMALLOC_FIRST_CLASS_HEAPS
		if (heap)
			p = (op % 12) ? rpmalloc_heap_aligned_zalloc(heap, 16, size) : rpmalloc_heap_alloc(heap, size);
		else
#endif
			p = (op % 12) ? rpzalloc(size) : rpmalloc(size);
		if (!p)
			{ if (rp_tolerate_null) return; rp_fail("allocation failed", s); }
		rp_adopt(t, s, p, size, 16, (op % 12) == 1, owner);
		return;
	case 2:  // calloc / aligned calloc
	case 3:
		rp_calloc_args(r, &num, &size);
		align = ((op % 12) == 3) ? rp_align(r) : 0;
		rp_free_slot(t, s, heaps);
		if (rp_mul_overflows(num, size)) {
#if RPMALLOC_FIRST_CLASS_HEAPS
			if (heap)
				p = align ? rpmalloc_heap_aligned_calloc(heap, align, num, size) : rpmalloc_heap_calloc(heap, num, size);
			else
#endif
				p = align ? rpaligned_calloc(align, num, size) : rpcalloc(num, size);
			if (p)
				rp_fail("calloc with an overflowing num*size returned a block", s);
			return;
		}
		if (!rp_room(t, num * size))
			return;
#if RPMALLOC_FIRST_CLASS_HEAPS
		if (heap)
			p = align ? rpmalloc_heap_aligned_calloc(heap, align, num, size) : rpmalloc_heap_calloc(heap, num, size);
		else
#endif
			p = align ? rpaligned_calloc(align, num, size) : rpcalloc(num, size);
		if (!p)
			{ if (rp_tolerate_null || align >= RPMALLOC_MAX_ALIGNMENT) return; rp_fail("calloc failed", s); }
		rp_adopt(t, s, p, num * size, align, 1, owner);
		return;
	case 4:  // aligned alloc family
	case 5:
	case 6: {
		int zeroed = ((op % 12) == 5);
		align = rp_align(r);
		size = rp_size(r);
		rp_free_slot(t, s, heaps);
		if (!rp_room(t, size))
			return;
#if RPMALLOC_FIRST_CLASS_HEAPS
		if (heap) {
			p = ((op % 12) == 5) ? rpmalloc_heap_aligned_zalloc(heap, align, size)
			                     : rpmalloc_heap_aligned_alloc(heap, align, size);
		} else
#endif
		{
			int kind = (op % 12) + (rp_u8(r) & 1) * 3;
			zeroed = (kind == 5) || (kind == 8);
			switch (kind) {
			case 4: p = rpaligned_alloc(align, size); break;
			case 5: p = rpaligned_zalloc(align, size); break;
			case 6: p = rpmemalign(align, size); break;
			case 7: p = rpaligned_alloc(align, size); break;
			case 8: p = rpaligned_zalloc(align, size); break;
			default:
				if (rpposix_memalign(&p, align, size) != 0)
					p = 0;
				break;
			}
		}
		if (!p)
			{ if (rp_tolerate_null || align >= RPMALLOC_MAX_ALIGNMENT) return; rp_fail("aligned allocation failed", s); }
		rp_adopt(t, s, p, size, align, zeroed, owner);
		return;
	}
	case 7:  // realloc
	case 8: {  // aligned realloc with flags
		if (!s->ptr)
			return;
		size = rp_size(r);
		unsigned int flags = 0;
		size_t oldsize = s->size;
		if ((op % 12) == 8) {
			align = rp_align(r);
			flags = rp_u8(r) & (RPMALLOC_NO_PRESERVE | RPMALLOC_GROW_OR_FAIL);
			if (rp_u8(r) & 1)
				oldsize = 0;  // let rpmalloc derive it from the block
		}
		if (!rp_room(t, size))
			return;
		rp_verify(s);
		rp_slot_t old = *s;
#if RPMALLOC_FIRST_CLASS_HEAPS
		if (heap)
			p = ((op % 12) == 8) ? rpmalloc_heap_aligned_realloc(heap, s->ptr, align, size, flags)
			                     : rpmalloc_heap_realloc(heap, s->ptr, size, 0);
		else
#endif
			p = ((op % 12) == 8) ? rpaligned_realloc(s->ptr, align, size, oldsize, flags) : rprealloc(s->ptr, size);
		if (!p) {
			if (!(flags & RPMALLOC_GROW_OR_FAIL) && !rp_tolerate_null && align < RPMALLOC_MAX_ALIGNMENT)
				rp_fail("realloc failed", s);
			rp_verify(s);  // a failed grow-or-fail realloc leaves the block untouched
			return;
		}
		rp_release_slot(t, s);
		s->ptr = (uint8_t*)p;
		s->size = size;
		s->align = align;
		s->owner = owner;
		if (align && ((uintptr_t)p % align))
			rp_fail("realloc result is not aligned", s);
		if (rpmalloc_usable_size(p) < size)
			rp_fail("usable size below the realloc size", s);
		if (!(flags & RPMALLOC_NO_PRESERVE))
			rp_verify_prefix(s, old.size < size ? old.size : size, old.pattern);
		s->pattern = (uint8_t)(++t->next_pattern | 1);
		rp_fill(s);
		t->live += size;
		return;
	}
	case 9:
	case 10:  // free
		rp_free_slot(t, s, heaps);
		return;
	default:  // collect deferred frees and caches of the thread heap
		if (!heap)
			rpmalloc_thread_collect();
		return;
	}
}

#endif
