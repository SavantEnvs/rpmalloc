// Fuzzes the standard library override layer (rpmalloc/malloc.c, compiled into rpmalloc.c with
// ENABLE_OVERRIDE=1): malloc, calloc, realloc, reallocarray, reallocarr, valloc, pvalloc,
// aligned_alloc, memalign, posix_memalign, malloc_usable_size, malloc_good_size, free, all
// routed to rpmalloc for the whole process (the fuzzer runtime included).
//
// Because rpmalloc replaces malloc here, this target is built WITHOUT AddressSanitizer (whose
// allocator would collide with the override); UBSan stays on and halting, ENABLE_ASSERTS=1 turns
// the allocator's invariants into aborts, and the harness self-checks every result: fill
// patterns survive realloc, alignment and page rounding are honoured, usable size covers the
// request and malloc_good_size, and count*size overflows in reallocarray/reallocarr fail
// (ENOMEM / EOVERFLOW) leaving the block untouched.
//
// Allocator state persists across inputs (it backs the whole process and cannot be finalized
// under the override); every block an input allocates is freed at its end.
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void* reallocarray(void* ptr, size_t count, size_t size);
extern int reallocarr(void* ptrp, size_t count, size_t size);
extern size_t malloc_good_size(size_t size);
extern void* pvalloc(size_t size);
extern void* valloc(size_t size);

#define SLOTS 32
#define MAX_BLOCK ((size_t)8 * 1024 * 1024)

typedef struct {
	uint8_t* ptr;
	size_t size;
	uint8_t pattern;
} slot_t;

static slot_t slots[SLOTS];
static uint8_t next_pattern;
static size_t page_size;

typedef struct {
	const uint8_t* data;
	size_t size, pos;
} reader_t;

static uint8_t
u8(reader_t* r) {
	return (r->pos < r->size) ? r->data[r->pos++] : 0;
}

static uint32_t
u32(reader_t* r) {
	uint32_t v = 0;
	for (int i = 0; i < 4; ++i)
		v |= (uint32_t)u8(r) << (8 * i);
	return v;
}

static size_t
fz_size(reader_t* r) {
	static const size_t limit[] = {128, 1024, 4096, 65536, 262144, 2097152, MAX_BLOCK, 16};
	uint8_t sel = u8(r);
	return u32(r) % (limit[sel & 7] + 1);
}

static void
fail(const char* what, const slot_t* s) {
	fprintf(stderr, "override self-check failed: %s (ptr=%p size=%zu)\n", what, (void*)(s ? s->ptr : 0),
	        s ? s->size : 0);
	abort();
}

static void
verify(const slot_t* s, size_t len, uint8_t pattern) {
	for (size_t i = 0; i < len; ++i)
		if (s->ptr[i] != pattern)
			fail("block content corrupted", s);
}

static void
adopt(slot_t* s, void* p, size_t size, size_t align, int zeroed) {
	s->ptr = (uint8_t*)p;
	s->size = size;
	if (align && ((uintptr_t)p % align))
		fail("block is not aligned", s);
	if (malloc_usable_size(p) < size)
		fail("usable size below the requested size", s);
	if (zeroed)
		verify(s, size, 0);
	s->pattern = (uint8_t)(++next_pattern | 1);
	memset(s->ptr, s->pattern, size);
}

static void
drop(slot_t* s) {
	if (!s->ptr)
		return;
	verify(s, s->size, s->pattern);
	free(s->ptr);
	s->ptr = 0;
	s->size = 0;
}

static void
moved(slot_t* s, void* p, size_t size) {
	slot_t old = *s;
	s->ptr = (uint8_t*)p;
	s->size = size;
	if (malloc_usable_size(p) < size)
		fail("usable size below the realloc size", s);
	verify(s, old.size < size ? old.size : size, old.pattern);
	s->pattern = (uint8_t)(++next_pattern | 1);
	memset(s->ptr, s->pattern, size);
}

int
LLVMFuzzerInitialize(int* argc, char*** argv) {
	(void)argc;
	(void)argv;
	page_size = (size_t)sysconf(_SC_PAGESIZE);
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	reader_t r = {data, size, 0};
	for (unsigned int ops = 0; r.pos < r.size && ops < 2048; ++ops) {
		uint8_t op = u8(&r);
		slot_t* s = &slots[u8(&r) % SLOTS];
		void* p = 0;
		size_t n = 0, count = 0, align = 0;
		switch (op % 13) {
		case 0:
			n = fz_size(&r);
			drop(s);
			if (!(p = malloc(n)))
				fail("malloc failed", s);
			if (malloc_good_size(n) < n || malloc_good_size(n) > malloc_usable_size(p))
				fail("malloc_good_size inconsistent with malloc_usable_size", s);
			adopt(s, p, n, 16, 0);
			break;
		case 1:
			n = u32(&r) % 4097;
			count = (u8(&r) & 1) ? ((size_t)1 << (40 + u8(&r) % 24)) : fz_size(&r) / (n ? n : 1);
			drop(s);
			if (__builtin_mul_overflow(count, n, &align)) {
				if ((p = calloc(count, n)) != 0)
					fail("calloc with an overflowing count*size returned a block", s);
				break;
			}
			if (count * n > MAX_BLOCK)
				break;  // a real terabyte request would only exhaust the address space
			p = calloc(count, n);
			if (!p)
				fail("calloc failed", s);
			adopt(s, p, count * n, 16, 1);
			break;
		case 2:
			if (!s->ptr)
				break;
			n = fz_size(&r);
			verify(s, s->size, s->pattern);
			if (!(p = realloc(s->ptr, n)))
				fail("realloc failed", s);
			moved(s, p, n);
			break;
		case 3:
		case 4: {
			// reallocarray (op 3) or reallocarr (op 4), the count*size product overflowing or not
			if (!s->ptr)
				break;
			n = 1 + u32(&r) % 4096;
			int want_overflow = u8(&r) & 1;
			if (want_overflow && n < 2)
				n = 2;  // SIZE_MAX / 1 + 1 wraps to 0, which would not overflow
			count = want_overflow ? (SIZE_MAX / n) + 1 + u8(&r) : fz_size(&r) / n;
			// The expected result follows the real product, not how count was built.
			size_t product;
			int overflow = __builtin_mul_overflow(count, n, &product);
			verify(s, s->size, s->pattern);
			if ((op % 13) == 3) {
				errno = 0;
				p = reallocarray(s->ptr, count, n);
				if (overflow) {
					if (p || errno != ENOMEM)
						fail("reallocarray accepted an overflowing count*size", s);
					verify(s, s->size, s->pattern);
					break;
				}
				if (!p)
					fail("reallocarray failed", s);
			} else {
				void* q = s->ptr;
				int rc = reallocarr(&q, count, n);
				if (overflow) {
					if (rc != EOVERFLOW || q != s->ptr)
						fail("reallocarr accepted an overflowing count*size", s);
					verify(s, s->size, s->pattern);
					break;
				}
				if (rc != 0)
					fail("reallocarr failed", s);
				if (!count) {
					if (q)
						fail("reallocarr to zero size did not clear the pointer", s);
					s->ptr = 0;
					s->size = 0;
					break;
				}
				p = q;
			}
			moved(s, p, count * n);
			break;
		}
		case 5:
		case 6:
			n = fz_size(&r);
			drop(s);
			p = ((op % 13) == 5) ? valloc(n) : pvalloc(n);
			if (!p)
				fail("valloc/pvalloc failed", s);
			if ((op % 13) == 6 && malloc_usable_size(p) < ((n + page_size - 1) / page_size) * page_size)
				fail("pvalloc block not rounded up to whole pages", s);
			adopt(s, p, n, page_size, 0);
			break;
		case 7:
		case 8:
		case 9: {
			align = (size_t)1 << (3 + u8(&r) % 16);
			n = fz_size(&r);
			drop(s);
			if ((op % 13) == 7)
				p = aligned_alloc(align, n);
			else if ((op % 13) == 8)
				p = memalign(align, n);
			else if (posix_memalign(&p, align, n) != 0)
				p = 0;
			if (!p) {
				if (align >= 256 * 1024)  // RPMALLOC_MAX_ALIGNMENT is rejected with EINVAL
					break;
				fail("aligned allocation failed", s);
			}
			adopt(s, p, n, align, 0);
			break;
		}
		default:
			drop(s);
			break;
		}
	}
	for (int i = 0; i < SLOTS; ++i)
		drop(&slots[i]);
	return 0;
}
