---

title: How2heap-Wargame-Writeup
lang: zh
layout: article
show_subscribe: false
tags: [wargame-ctf]

---


**跟我一起Wargame.**


本文是[Educational Heap Exploitation Wargame](https://github.com/shellphish/how2heap)系列writeup。Wargame的一个优点就是现学现用。

持续更新中。。。

## 实验环境

* x86_64 GNU/Linux 5.13.0-44-generic
* gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)



## FIRST_FIT.C

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	fprintf(stderr, "This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
	fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
	fprintf(stderr, "If a chunk is free and large enough, malloc will select this chunk.\n");
	fprintf(stderr, "This can be exploited in a use-after-free situation.\n");

	fprintf(stderr, "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
	char* a = malloc(0x512);
	char* b = malloc(0x256);
	char* c;

	fprintf(stderr, "1st malloc(0x512): %p\n", a);
    /* 1st malloc(0x512): 0x557978fdf2a0  */
	fprintf(stderr, "2nd malloc(0x256): %p\n", b);
    /* 2nd malloc(0x256): 0x557978fdf7c0 */
	fprintf(stderr, "we could continue mallocing here...\n");
	fprintf(stderr, "now let's put a string at a that we can read later \"this is A!\"\n");
	strcpy(a, "this is A!");
	fprintf(stderr, "first allocation %p points to %s\n", a, a);
    /* first allocation 0x557978fdf2a0 points to this is A! */
	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at %p\n", a);
    /* We don't need to free anything again.
     * As long as we allocate smaller than 0x512, 
     * it will end up at 0x557978fdf2a0 
     * */
	fprintf(stderr, "So, let's allocate 0x500 bytes\n");
	c = malloc(0x500);
	fprintf(stderr, "3rd malloc(0x500): %p\n", c);
    /* 3rd malloc(0x500): 0x557978fdf2a0 */
	fprintf(stderr, "And put a different string here, \"this is C!\"\n");
	strcpy(c, "this is C!");
	fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
    /*  3rd allocation 0x557978fdf2a0 points to this is C! */
	fprintf(stderr, "first allocation %p points to %s\n", a, a);
    /* first allocation 0x557978fdf2a0 points to this is C! */
	fprintf(stderr, "If we reuse the first allocation, it now holds the data from the third allocation.\n");
}

```

已经把我的运行情况注释出来了。


## calc_tcache_idx.c


**一些术语：**

1. [bins的概念](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/)：

> As memory gets passed back to free, the heap manager tracks these freed chunks in a series of different linked lists called “bins”.

> For performance reasons, there are several different types of bins, i.e. fast bins, the unsorted bin, small bins, large bins, and the per-thread tcache. 


2.

`calc_tcache_idx.c`源码中给出这部分的代码,就是[malloc源码中对chunk的描述](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=6e766d11bc85b6480fa5c9f2a76559f8acf9deb5;hb=HEAD#l1038)：

```cpp
struct malloc_chunk {

  size_t      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  size_t      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

```

size_t 在32位机器上是4字节，64位机器上是8字节。


> The mchunk_size stores four pieces of information: the chunk size, and three bits called “A”, “M”, and “P”. These can all be stored in the same size_t field because chunk sizes are always 8-byte aligned (or 16-byte aligned on 64-bit), and therefore the low three bits of the chunk size are always zero.

63个 Large bins

