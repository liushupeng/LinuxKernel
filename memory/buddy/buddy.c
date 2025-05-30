#include "buddy.h"
#include <assert.h>
#include <stdio.h>

void buddy_system_init(struct mem_zone* zone, unsigned long page_num)
{
    // init other memory zone field
    zone->page_num  = page_num;
    zone->page_size = BUDDY_PAGE_SIZE;
    zone->end_addr  = zone->start_addr + zone->page_num * zone->page_size;

    // init each free_area's list
    for (unsigned long i = 0; i < BUDDY_MAX_ORDER; i++) {
        struct free_area* area = zone->free_area + i;
        INIT_LIST_HEAD(&area->free_list);
        area->nr_free = 0;
    }

    // free each page to free_area
    memset(zone->first_page, 0x00, zone->page_num * sizeof(struct page));
    for (unsigned long i = 0; i < zone->page_num; i++) {
        struct page* page = zone->first_page + i;
        INIT_LIST_HEAD(&page->lru);
        buddy_free_pages(zone, page);
    }
}

static void set_page_attributes(struct page* page, unsigned long order)
{
    if (order == 0) {
        clear_buddy_order_flag(page);
    }
    else {
        unsigned long nr_pages = (1UL << order);
        set_head_order_flag(page, order);

        for (unsigned long i = 1; i < nr_pages; i++) {
            set_tail_order_flag(page + i, page);
        }
    }
}

/*
 * Split the compound page in half, place the latter half back in the buddy system,
 * and continue to split the first half until it is the appropriate size.
 * In this way, the page* can be directly used as the return value.
 */
static void split_page(struct mem_zone* zone, struct page* page, unsigned long low_order,
                       unsigned long high_order)
{
    for (; high_order > low_order; high_order--) {
        unsigned long     nr_pages = 1U << high_order;
        struct free_area* area     = zone->free_area + high_order;

        // Place the latter half back in the buddy system
        area->nr_free++;
        list_add(&page[nr_pages].lru, &area->free_list);
        set_buddy_order_flag(page + nr_pages, high_order);
    }
}

static struct page* __alloc_page(struct mem_zone* zone, unsigned long order)
{
    struct page*      page = NULL;
    struct free_area* area = NULL;

    for (unsigned long cur_order = order; cur_order < BUDDY_MAX_ORDER; cur_order++) {
        area = zone->free_area + cur_order;
        if (list_empty(&area->free_list)) {
            continue;
        }

        // Retrieve a page from the free_list of current order
        page = list_entry(area->free_list.next, struct page, lru);
        list_del(&page->lru);
        area->nr_free--;

        // If current order size not meet, split the page into appropriate sizes
        if (cur_order > order) {
            split_page(zone, page, order, cur_order - 1);
        }

        set_page_attributes(page, order);

        return page;
    }
    return NULL;
}

struct page* buddy_alloc_pages(struct mem_zone* zone, unsigned long order)
{
    if (order >= BUDDY_MAX_ORDER) {
        BUDDY_BUG(__FILE__, __LINE__);
        return NULL;
    }
    return __alloc_page(zone, order);
}

static int clear_compound_flag(struct page* page, unsigned long order)
{
    unsigned long nr_pages = (1UL << order);

    __ClearPageHead(page);
    for (unsigned long i = 1; i < nr_pages; i++) {
        if (!PageTail(page + i) || page[i].first_page != page) {
            return -1;
        }
        __ClearPageTail(page + i);
    }
    return 0;
}

void buddy_free_pages(struct mem_zone* zone, struct page* page)
{
    unsigned long order = get_order(page);

    if (PageCompound(page)) {
        if (clear_compound_flag(page, order)) {
            BUDDY_BUG(__FILE__, __LINE__);
        }
    }

    for (unsigned long page_idx = page - zone->first_page; order < BUDDY_MAX_ORDER - 1; order++) {
        unsigned long buddy_idx  = __find_buddy_index(page_idx, order);
        struct page*  buddy_page = page + (buddy_idx - page_idx);

        // Buddy page is not in buddy system, not need combind
        if (!(PageBuddy(buddy_page) && (buddy_page->order == order))) {
            break;
        }

        // Remove buddy page from buddy system
        list_del(&buddy_page->lru);
        zone->free_area[order].nr_free--;
        clear_buddy_order_flag(buddy_page);

        // Update page and page_idx after combined
        unsigned long combinded_idx = __find_combined_index(page_idx, order);
        page                        = page + (combinded_idx - page_idx);
        page_idx                    = combinded_idx;
    }

    set_buddy_order_flag(page, order);
    list_add(&page->lru, &zone->free_area[order].free_list);
    zone->free_area[order].nr_free++;
}

unsigned long buddy_free_page_count(struct mem_zone* zone)
{
    unsigned long count = 0;
    for (unsigned long i = 0; i < BUDDY_MAX_ORDER; i++) {
        count += zone->free_area[i].nr_free * (1UL << i);
    }
    return count;
}

void dump_print(struct mem_zone* zone)
{
    printf("order   (npage)      nr_free\n");
    for (unsigned long i = 0; i < BUDDY_MAX_ORDER; i++) {
        printf("  %ld\t(2^%ld=%-3ld)\t%ld\n", i, i, 1UL << i, zone->free_area[i].nr_free);
    }
}

void dump_print_png(struct mem_zone* zone, const char* filename)
{
    char dot_file[32];

    snprintf(dot_file, sizeof(dot_file), "%s.dot", filename);
    FILE* fout = fopen(dot_file, "w");
    assert(fout);

    // 1. graph header
    fprintf(fout, "digraph g {\n");
    fprintf(fout, "graph [rankdir=LR];\n");
    fprintf(fout, "edge [dir=both,arrowsize=.5];\n");
    fprintf(fout, "node [shape=record,height=.1];\n");
    fprintf(fout, "\n");

    // 2. free_area
    fprintf(fout, "free_area [label = \"");
    for (unsigned long i = 0; i < BUDDY_MAX_ORDER; i++) {
        fprintf(fout, "<%ld>2^%ld,%ld", i, i, zone->free_area[i].nr_free);
        if (i + 1 != BUDDY_MAX_ORDER) {
            fprintf(fout, "|");
        }
    }
    fprintf(fout, "\"];\n\n");
    fprintf(fout, "pages [style=filled,color=gray,label = \"{");
    for (long i = zone->page_num - 1, k = 0; i >= 0; i--) {
        if (PageBuddy(&zone->first_page[i])) {
            if (k == 0) {
                k = 1;
            }
            else {
                fprintf(fout, "|");
            }
            fprintf(fout, "<%ld>%ld~%ld", i, i + (1UL << zone->first_page[i].order), i);
        }
    }
    fprintf(fout, "}\"];\n\n");

    // 3. each list in free area
    for (unsigned long i = 0; i < BUDDY_MAX_ORDER; i++) {
        long              j = 0;
        struct list_head* pos;

        fprintf(fout, "// area %ld\n", i);
        // each node in list
        list_for_each(pos, &zone->free_area[i].free_list)
        {
            struct page*  page     = list_entry(pos, struct page, lru);
            unsigned long page_idx = page - zone->first_page;
            fprintf(fout, "node%ld_%ld [label = \"{%ld}\"];", i, j, page_idx);
            fprintf(fout, "node%ld_%ld -> pages:%ld;\n", i, j, page_idx);
            j++;
        }
        // connect nodes
        for (long k = 0; k < j; k++) {
            if (k == 0) {
                fprintf(fout, "free_area:%ld -> node%ld_%ld;\n", i, i, k);
            }
            else {
                fprintf(fout, "node%ld_%ld -> node%ld_%ld;\n", i, k - 1, i, k);
            }
        }
        fprintf(fout, "\n");
    }

    // 4. graph end
    fprintf(fout, "\n");
    fprintf(fout, "}\n");
    fclose(fout);

    // 5. convert dot to png
    char command[128];
    snprintf(
        command, sizeof(command), "dot %s -Tpng -o%s && rm -f %s", dot_file, filename, dot_file);

    FILE* fp = popen(command, "r");
    if (fp == NULL) {
        printf("popen %s failed\n", command);
        return;
    }

    pclose(fp);
}

void* page_to_virtual(struct mem_zone* zone, struct page* page)
{
    unsigned long page_idx = page - zone->first_page;
    unsigned long address  = zone->start_addr + page_idx * BUDDY_PAGE_SIZE;

    return (void*)address;
}

struct page* virtual_to_page(struct mem_zone* zone, void* ptr)
{
    unsigned long address = (unsigned long)ptr;

    if ((address < zone->start_addr) || (address > zone->end_addr)) {
        printf("start_addr=0x%lx, end_addr=0x%lx, address=0x%lx\n",
               zone->start_addr,
               zone->end_addr,
               address);
        BUDDY_BUG(__FILE__, __LINE__);
        return NULL;
    }

    unsigned long page_idx = (address - zone->start_addr) >> BUDDY_PAGE_SHIFT;
    struct page*  page     = zone->first_page + page_idx;

    return page;
}
