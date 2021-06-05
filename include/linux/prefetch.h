/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Generic cache management functions. Everything is arch-specific,  
 *  but this header exists to make sure the defines/functions can be
 *  used in a generic way.
 *
 *  2000-11-13  Arjan van de Ven   <arjan@fenrus.demon.nl>
 *
 */

#ifndef _LINUX_PREFETCH_H
#define _LINUX_PREFETCH_H

#include <linux/types.h>
#include <asm/processor.h>
#include <asm/cache.h>

struct page;
/*
	prefetch(x) attempts to pre-emptively get the memory pointed to
	by address "x" into the CPU L1 cache. 
	prefetch(x) should not cause any kind of exception, prefetch(0) is
	specifically ok.

	prefetch() should be defined by the architecture, if not, the 
	#define below provides a no-op define.	
	
	There are 3 prefetch() macros:
	
	prefetch(x)  	- prefetches the cacheline at "x" for read
	prefetchw(x)	- prefetches the cacheline at "x" for write
	spin_lock_prefetch(x) - prefetches the spinlock *x for taking
	
	there is also PREFETCH_STRIDE which is the architecure-preferred 
	"lookahead" size for prefetching streamed operations.

prefetch(x) 尝试抢先获取指向的内存
通过地址“x”进入 CPU L1 缓存。
prefetch(x) 不应导致任何类型的异常， prefetch(0) 是
具体可以。

prefetch() 应该由架构定义，如果不是，则
#define 下面提供了一个无操作定义。

有 3 个 prefetch() 宏：

prefetch(x) - 在“x”处预取缓存行以供读取
prefetchw(x) - 在“x”处预取缓存行以进行写入
spin_lock_prefetch(x) - 预取自旋锁 *x 以供获取

还有 PREFETCH_STRIDE 是架构首选
预取流式操作的“前瞻”大小。 

	
*/

#ifndef ARCH_HAS_PREFETCH
#define prefetch(x) __builtin_prefetch(x)
#endif

#ifndef ARCH_HAS_PREFETCHW
#define prefetchw(x) __builtin_prefetch(x,1)
#endif

#ifndef ARCH_HAS_SPINLOCK_PREFETCH
#define spin_lock_prefetch(x) prefetchw(x)
#endif

#ifndef PREFETCH_STRIDE
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)
#endif

static inline void prefetch_range(void *addr, size_t len)
{
#ifdef ARCH_HAS_PREFETCH
	char *cp;
	char *end = addr + len;

	for (cp = addr; cp < end; cp += PREFETCH_STRIDE)
		prefetch(cp);
#endif
}

static inline void prefetch_page_address(struct page *page)
{
#if defined(WANT_PAGE_VIRTUAL) || defined(HASHED_PAGE_VIRTUAL)
	prefetch(page);
#endif
}

#endif
