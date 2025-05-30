#ifndef __BUDDY_H__
#define __BUDDY_H__

#include "list.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define BUDDY_PAGE_SHIFT (12UL)
#define BUDDY_PAGE_SIZE (1UL << BUDDY_PAGE_SHIFT)   // 4K
#define BUDDY_MAX_ORDER (9UL)

/*
 * There are two type pages:
 * - single page (order=0).
 * - compound page (order>0).
 *   The first part of the compound page is the PG_head, and the rest are the PG_tail.
 */

enum pageflags
{
    PG_head,    // Not in buddy system, first page
    PG_tail,    // Not in buddy system, outside the first page
    PG_buddy,   // In buddy system
};

struct page
{
    struct list_head lru;
    unsigned long    flags;   // Assigned by enum pageflags
    union
    {
        unsigned long order;        // PG_head use this field
        struct page*  first_page;   // PG_tail use this field, point to the head page
    };
};

struct free_area
{
    struct list_head free_list;
    unsigned long    nr_free;
};

struct mem_zone
{
    struct page*  first_page;
    unsigned long page_num;
    unsigned long page_size;

    unsigned long start_addr;
    unsigned long end_addr;

    struct free_area free_area[BUDDY_MAX_ORDER];
};

/*
 * Init buddy system
 */
void buddy_system_init(struct mem_zone* zone, unsigned long page_num);

/*
 * Allocator pages from buddy system
 */
struct page* buddy_alloc_pages(struct mem_zone* zone, unsigned long order);

/*
 * Free pages to buddy system
 */
void buddy_free_pages(struct mem_zone* zone, struct page* page);

/*
 * Get the count of buddy system free page
 */
unsigned long buddy_free_page_count(struct mem_zone* zone);

/*
 * Print buddy system status in text format
 */
void dump_print(struct mem_zone* zone);

/*
 * Print buddy system status in image format
 */
void dump_print_png(struct mem_zone* zone, const char* filename);

static void __SetPageHead(struct page* page)
{
    page->flags |= (1UL << PG_head);
}

static void __SetPageTail(struct page* page)
{
    page->flags |= (1UL << PG_tail);
}

static void __SetPageBuddy(struct page* page)
{
    page->flags |= (1UL << PG_buddy);
}

static void __ClearPageHead(struct page* page)
{
    page->flags &= ~(1UL << PG_head);
}

static void __ClearPageTail(struct page* page)
{
    page->flags &= ~(1UL << PG_tail);
}

static void __ClearPageBuddy(struct page* page)
{
    page->flags &= ~(1UL << PG_buddy);
}

static int PageHead(struct page* page)
{
    return (page->flags & (1UL << PG_head));
}

static int PageTail(struct page* page)
{
    return (page->flags & (1UL << PG_tail));
}

static int PageBuddy(struct page* page)
{
    return (page->flags & (1UL << PG_buddy));
}

static int PageCompound(struct page* page)
{
    return (page->flags & ((1UL << PG_head) | (1UL << PG_tail)));
}

/*
 * This buddy system records the order of the compound page in the page->order field of the head
 * page. Therefore, if it is not a head page, it is a single page
 */
static unsigned long get_order(struct page* page)
{
    return PageHead(page) ? page->order : 0;
}

static void set_head_order_flag(struct page* page, unsigned long order)
{
    page->order = order;
    __SetPageHead(page);
}

static void set_tail_order_flag(struct page* page, struct page* head_page)
{
    page->first_page = head_page;
    __SetPageTail(page);
}

static void set_buddy_order_flag(struct page* page, unsigned long order)
{
    page->order = order;
    __SetPageBuddy(page);
}

static void clear_buddy_order_flag(struct page* page)
{
    page->order = 0;
    __ClearPageBuddy(page);
}

/*
 * Find the buddy index at the order level
 */
static unsigned long __find_buddy_index(unsigned long page_idx, unsigned int order)
{
    return (page_idx ^ (1 << order));
}

/*
 * Find the new index of the combined page
 */
static unsigned long __find_combined_index(unsigned long page_idx, unsigned int order)
{
    return (page_idx & ~(1 << order));
}

static void BUDDY_BUG(const char* f, int line)
{
    printf("BUDDY_BUG in %s, %d.\n", f, line);
    assert(0);
}

#endif
