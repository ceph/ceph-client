#include "ceph_debug.h"

#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>

#define CEPH_OVERRIDE_BOOKKEEPER /* avoid kmalloc/kfree recursion */

#define CEPH_BK_MAGIC 0x140985AC

int ceph_debug_tools __read_mostly = -1;
#define DOUT_VAR ceph_debug_tools
#define DOUT_MASK DOUT_MASK_TOOLS
#include "super.h"

static struct list_head _bk_allocs;

static DEFINE_SPINLOCK(_bk_lock);

static size_t _total_alloc;
static size_t _total_free;
static size_t _total_kc_alloc;
static size_t _total_kc_free;

#define ALLOC_TYPE_KALLOC	0x1
#define ALLOC_TYPE_KMEMCACHE	0x2

struct alloc_data {
	u32 prefix_magic;
	size_t size;
	int alloc_type;
	struct list_head node;
	const char *fname;
	int line;
	u32 suffix_magic;
};

struct ceph_kmemcache {
	struct kmem_cache *cache;
	size_t alloc_size;
	void (*ctor)(void *);
};

static void bk_init_header(struct alloc_data *header, size_t size, int alloc_type)
{
	header->prefix_magic = CEPH_BK_MAGIC;
	header->size = size;
	header->alloc_type = alloc_type;
	header->suffix_magic = CEPH_BK_MAGIC;
}

static void bk_insert_alloc(struct alloc_data *header, const char *fname, int line, size_t size)
{
	header->line = line;
	header->fname = fname;

	spin_lock(&_bk_lock);
	_total_alloc += size;
	if (header->alloc_type == ALLOC_TYPE_KMEMCACHE) {
		_total_kc_alloc += size;
	}

	list_add_tail(&header->node, &_bk_allocs);
	spin_unlock(&_bk_lock);
}

static void bk_remove_alloc(struct alloc_data *header)
{
	int overrun = 0;

	if (header->prefix_magic != CEPH_BK_MAGIC) {
		printk(KERN_ERR "ERROR: memory overrun (under)!\n");
		overrun = 1;
	}

	if (header->suffix_magic != CEPH_BK_MAGIC) {
		printk(KERN_ERR "ERROR: Memory overrun (over)!\n");
		overrun = 1;
	}

	if (overrun) {
		printk(KERN_ERR "Memory allocated at %s(%d): p=%p (%zu bytes)\n",
		     header->fname, header->line, ((void *)header)+sizeof(struct alloc_data),
		     header->size);
	}

	BUG_ON(overrun);

	spin_lock(&_bk_lock);
	_total_free += header->size;
	if (header->alloc_type == ALLOC_TYPE_KMEMCACHE) {
		_total_kc_free += header->size;
	}
	list_del(&header->node);
	spin_unlock(&_bk_lock);
}

struct kmem_cache *
ceph_kmem_cache_create(const char *name, size_t size, size_t align,
			     unsigned long flags, void (*ctor)(void *))
{
	struct ceph_kmemcache *ceph_cache;

	ceph_cache = (struct ceph_kmemcache *)kmalloc(
						sizeof(struct ceph_kmemcache),
						GFP_KERNEL);
	if (!ceph_cache)
		return NULL;


	ceph_cache->cache = kmem_cache_create(name, size + sizeof(struct alloc_data),
				__alignof__(align + sizeof(struct alloc_data)),
				flags, NULL);
	ceph_cache->alloc_size = size; 
	ceph_cache->ctor = ctor;

	return (struct kmem_cache *)ceph_cache;
}

void ceph_kmem_cache_destroy(struct kmem_cache *cachep)
{
	struct ceph_kmemcache *ceph_cache = (struct ceph_kmemcache *)cachep;

	kmem_cache_destroy(ceph_cache->cache);

	kfree(ceph_cache);
}

void *ceph_kmem_cache_alloc(char *fname, int line, struct kmem_cache *cachep,
		           gfp_t flags)
{
	struct ceph_kmemcache *ceph_cache = (struct ceph_kmemcache *)cachep;
	struct alloc_data *header =
		(struct alloc_data *)kmem_cache_alloc(ceph_cache->cache, flags);
	void *p;

	if (!header) {
		printk(KERN_ERR "%s.%d: failed to allocate %d bytes", fname, line, (int)ceph_cache->alloc_size);
		return NULL;
	}

	p = (void *)(header + 1);

	if (header->prefix_magic != CEPH_BK_MAGIC) {
		bk_init_header(header, ceph_cache->alloc_size, ALLOC_TYPE_KMEMCACHE);

		if (ceph_cache->ctor)
			ceph_cache->ctor(p);
	}
	bk_insert_alloc(header, fname, line, ceph_cache->alloc_size);

	return p;
}

void ceph_kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	struct ceph_kmemcache *ceph_cache = (struct ceph_kmemcache *)cachep;
	struct alloc_data *p = (struct alloc_data *)(objp -
						     sizeof(struct alloc_data));
	
	bk_remove_alloc(p);
	kmem_cache_free(ceph_cache->cache, p);
}


void *ceph_kmalloc(char *fname, int line, size_t size, gfp_t flags)
{
	struct alloc_data *p = kmalloc(size+sizeof(struct alloc_data), flags);

	if (!p) {
		printk(KERN_ERR "%s.%d: failed to allocate %d bytes", fname, line, (int)size);
		return NULL;
	}

	bk_init_header(p, size, ALLOC_TYPE_KALLOC);
	bk_insert_alloc(p, fname, line, size);

	return (void *)(p + 1);
}

void ceph_kfree(const void *ptr)
{
	struct alloc_data *p = (struct alloc_data *)(ptr -
						     sizeof(struct alloc_data));
	if (!ptr)
		return;

	bk_remove_alloc(p);

	kfree(p);

	return;
}


void ceph_bookkeeper_dump(void)
{
	struct list_head *p;
	struct alloc_data *entry;

	printk(KERN_ERR "bookkeeper: total bytes alloc: %zu\n", _total_alloc);
	printk(KERN_ERR "bookkeeper: total bytes free: %zu\n", _total_free);
	printk(KERN_ERR "bookkeeper: (kmem_cache) total bytes alloc: %zu\n", _total_kc_alloc);
	printk(KERN_ERR "bookkeeper: (kmem_cache) total bytes free: %zu\n", _total_kc_free);

	if (_total_alloc != _total_free) {
		list_for_each(p, &_bk_allocs) {
			entry = list_entry(p, struct alloc_data, node);
			printk(KERN_ERR "%s(%d): p=%p (%zu bytes)\n", entry->fname,
			     entry->line,
			     ((void *)entry)+sizeof(struct alloc_data),
			     entry->size);
		}
	} else {
		printk(KERN_ERR "No leaks found! Yay!\n");
	}
}

char *ceph_kstrdup(char *fname, int line, const char *src, gfp_t flags)
{
	int len;
	char *dst;

	if (!src)
		return NULL;

	len = strlen(src);
	dst = ceph_kmalloc(fname, line, len + 1, flags);
	if (!dst)
		return NULL;

	memcpy(dst, src, len);
	dst[len] = '\0';

	return dst;
}

char *ceph_kstrndup(char *fname, int line, const char *src, int n, gfp_t flags)
{
	int len;
	char *dst;

	if (!src)
		return NULL;

	len = strlen(src);
	if (len > n)
		len = n;

	dst = ceph_kmalloc(fname, line, len + 1, flags);
	if (!dst)
		return NULL;

	memcpy(dst, src, len);
	dst[len] = '\0';

	return dst;
}

void ceph_bookkeeper_init(void)
{
	printk(KERN_ERR "bookkeeper: start\n");
	dout("bookkeeper: start\n");
	INIT_LIST_HEAD(&_bk_allocs);

	_total_alloc = 0;
	_total_free = 0;
	_total_kc_alloc = 0;
	_total_kc_free = 0;
}

void ceph_bookkeeper_finalize(void)
{
	ceph_bookkeeper_dump();
}
