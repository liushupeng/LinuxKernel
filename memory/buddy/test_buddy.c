/*
 * Based on code from https://github.com/godspeed1989/buddy_allocator
 * Original Author: godspeed1989 <godspeed1989@gmail.com>
 */

#include "buddy.h"
#include <stdlib.h>
#include <time.h>

#define PAGE_NUM 1024
#define RUN_SECONDS 20

static struct mem_zone global_zone;

static int mem_block_init(void)
{
    // pages area
    global_zone.first_page = (struct page*)malloc(PAGE_NUM * sizeof(struct page));
    // address area (optional)
    global_zone.start_addr = (unsigned long)malloc(PAGE_NUM * BUDDY_PAGE_SIZE);

    if (global_zone.first_page == NULL || global_zone.start_addr == 0) {
        return -1;
    }

    // init buddy
    buddy_system_init(&global_zone, PAGE_NUM);
    return 0;
}

static void mem_block_destroy(void)
{
    if (global_zone.first_page != NULL) {
        free((void*)global_zone.first_page);
    }
    if (global_zone.start_addr != 0) {
        free((void*)global_zone.start_addr);
    }
}

void buddy_test()
{
    time_t           start = time(NULL);
    struct page*     page;
    struct list_head page_list;
    unsigned long    loop;
    struct mem_zone* zone = &global_zone;

    srand((unsigned int)start);
    INIT_LIST_HEAD(&page_list);

    // run n seconds test
    for (loop = 0; loop % 1000 || time(NULL) - start < RUN_SECONDS; loop++) {
        if (rand() & 1) {   // allocate
            unsigned long order = (unsigned long)rand() % BUDDY_MAX_ORDER;
            page                = buddy_alloc_pages(zone, order);
            if (page) {
                list_add(&page->lru, &page_list);
            }
        }
        else if (!list_empty(&page_list)) {   // free
            page = list_entry(page_list.next, struct page, lru);
            list_del(&page->lru);
            buddy_free_pages(zone, page);
        }
    }
    printf("Buddy System Test: %ld loops in %ld s\n", loop, (unsigned long)(time(NULL) - start));
}

int main(void)
{
    if (mem_block_init() < 0) {
        mem_block_destroy();
        return -1;
    }
    printf("Memory block init done.\n");

    dump_print(&global_zone);
    printf("free page count: %ld\n", buddy_free_page_count(&global_zone));
    dump_print_png(&global_zone, "before_test.png");

    buddy_test();

    dump_print(&global_zone);
    printf("free page count: %ld\n", buddy_free_page_count(&global_zone));
    dump_print_png(&global_zone, "after_test.png");

    for (unsigned long i = 0; i < BUDDY_MAX_ORDER; i++) {
        struct page* p = buddy_alloc_pages(&global_zone, i);
        if (p) {
            buddy_free_pages(&global_zone, p);
        }
    }

    mem_block_destroy();
    return 0;
}
