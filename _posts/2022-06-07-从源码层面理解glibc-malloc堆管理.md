---
title: glibc malloc源码分析
lang: zh
layout: article
show_subscribe: false
tags: [linux,glibc,源码分析]

---

**未完待续...**

最开始是对堆上面的漏洞利用感兴趣。后来看到《CSAPP》中有个实验是自己[实现一个malloc](http://csapp.cs.cmu.edu/3e/labs.html),但想着自己写的没有malloc好,于是就想分析一下malloc的管理算法。主要是这么几个问题：

1. 堆上有哪些可能的漏洞利用点(最开始的问题)。
2. malloc在分配的时候如何权衡其分配的吞吐率与内存利用率的(两个矛盾的点)。
3. malloc 是如何处理多线程的堆请求的。
4. 学习一下高质量代码。

在看这篇文章之前，你至少需要了解：

1. bins的概念。
2. arena的概念。

如果不知道,没关系,可以先看一下下面这两篇文章，对malloc有一个总体上的粗粒度的了解：

[PART 1: UNDERSTANDING THE GLIBC HEAP IMPLEMENTATION](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/)

[PART 2: UNDERSTANDING THE GLIBC HEAP IMPLEMENTATION](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)

下面让我们对malloc有一个细粒度的了解。

## 调试环境搭建：

根据这个回答[Include source code of malloc.c in gdb?](https://stackoverflow.com/questions/29955609/include-source-code-of-malloc-c-in-gdb),下载源码用GDB调试。

调试主要是跟踪一下数据&控制流,找到malloc的入口点。

所用的glibc 版本：glibc-2.31

根据[12 C Preprocessor Macros](https://sourceware.org/gdb/current/onlinedocs/gdb/Macros.html#FOOT14),我们现在编译带调试信息的库(关键是宏扩展)：

```bash
$ ../glibc-2.31/configure --prefix=/home/z1933/Downloads/glibc-install/   CFLAGS='-gdwarf-2 -g3 -O3'
$ make all && make install
```

用环境变量使动态链接器优先链接我们的带调试信息的malloc。

```bash
$ export LD_PRELOAD=/home/z1933/Downloads/glibc-install/lib/libc-2.31.so 

$ ldd first_fit
	linux-vdso.so.1 (0x00007ffff7fcd000)
	/home/z1933/Downloads/glibc-install/lib/libc-2.31.so (0x00007ffff7dd6000)
	/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fcf000)

```

在gdb里面需要：
```
(gdb) dir /usr/src/glibc/glibc-2.31/malloc/
```

好了，现在可以在动态运行的时候展开一些宏。

Now I want to marry gdb：

```
┌──malloc.c───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│   1795          for (i = 1; i < NBINS; ++i)                                                                         │
│   1796            {                                                                                                 │
│   1797              bin = bin_at (av, i);                                                                           │
│   1798              bin->fd = bin->bk = bin;                                                                        │
│   1799            }                                                                                                 │
│   1800                                                                                                              │
│   1801        #if MORECORE_CONTIGUOUS                                                                               │
│   1802          if (av != &main_arena)                                                                              │
│   1803        #endif                                                                                                │
│b+ 1804          set_noncontiguous (av);                                                                             │
│   1805          if (av == &main_arena)                                                                              │
│  >1806            set_max_fast (DEFAULT_MXFAST);                                                                    │
│   1807          atomic_store_relaxed (&av->have_fastchunks, false);                                                 │
│   1808                                                                                                              │
│   1809          av->top = initial_top (av);                                                                         │
│   1810        }                                                                                                     │
│   1811                                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
native process 418301 In: ptmalloc_init                                                       L1806 PC: 0x7ffff7e74f15 
$6 = 128
(gdb) p DEFAULT_MXFAST
+p DEFAULT_MXFAST
$7 = 128
(gdb) macro expand set_max_fast (DEFAULT_MXFAST)
+macro expand set_max_fast (DEFAULT_MXFAST)
expands to: global_max_fast = ((((64 * (sizeof (size_t)) / 4)) == 0) ? (__builtin_offsetof (struct malloc_chunk, fd_nex
tsize)) / 2 : (((64 * (sizeof (size_t)) / 4) + (sizeof (size_t))) & ~((2 * (sizeof (size_t)) < __alignof__ (long double
) ? __alignof__ (long double) : 2 * (sizeof (size_t))) - 1)))
(gdb) 

```

## 测试代码 

先分析单线程。

测试代码基于[how2heap-first_fit](https://github.com/shellphish/how2heap/blob/master/first_fit.c),把输出都的删去了。

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	char* a = malloc(0x512);
	char* b = malloc(0x256);
	char* c;

	strcpy(a, "this is A!");
	free(a);
    /* We don't need to free anything again.
     * As long as we allocate smaller than 0x512, 
     * */
	c = malloc(0x500);
	strcpy(c, "this is C!");
}
```

```bash
$ gcc -g first_fit.c -o first_fit
```

## malloc入口点分析

源代码进入malloc函数:

```cpp
7     char* a = malloc(0x512);
```

程序先进入[malloc函数入口点](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/malloc.c#L3022)。执行下面语句。
```cpp
3030   void *(*hook) (size_t, const void *)
3031     = atomic_forced_read (__malloc_hook);

```

一层一层看，先从里层看起。[\__malloc_hook的初始化](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/malloc.c#L1847)：

```cpp
1847 void *weak_variable (*__malloc_hook)// 弱类型 初始化malloc hook为 malloc_hook_ini函数
1848   (size_t __size, const void *) = malloc_hook_ini;

```

`weak_variable`表示弱类型,用户可以覆盖其定义用于malloc的hook调试。这里我们分析默认初始化流程。这里就是将`__malloc_hook`函数指针初始化为[malloc_hook_ini函数](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/hooks.c#L28)地址,这个函数等到调用的时候我们再分析。

> 关于弱类型可以参考:[What are weak functions and what are their uses? I am using a stm32f429 micro controller](https://stackoverflow.com/questions/35507446/what-are-weak-functions-and-what-are-their-uses-i-am-using-a-stm32f429-micro-co)。


然后是外层的atomic_forced_read语句,[atomic_forced_read的实现](https://elixir.free-electrons.com/glibc/glibc-2.31/source/include/atomic.h#L524)为：。

```cpp
522 // 函数指针_x的类型：void *(*)(size_t __size, const void *)
523 #ifndef atomic_forced_read
524 # define atomic_forced_read(x) \
525   ({ __typeof (x) __x; __asm ("" : "=r" (__x) : "0" (x)); __x; })     
526 #endif

```

GCC 的`extended inline assembly`汇编语句。这里的意思就是把x的值赋值给声明的同类型_x。接着把_x赋值给外层的[void *(*hook) (size_t, const void *)](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/malloc.c#L3030)指针。这里原子读保证读到寄存器里面而不是从内存再读一次值(内存中再次读值可能会被其他线程改)。具体可以参考[What is the purpose of glibc's atomic_forced_read function?](https://stackoverflow.com/questions/58082597/what-is-the-purpose-of-glibcs-atomic-forced-read-function)。

> extended inline assembly 可以参考[Inline assembly](https://0xax.gitbooks.io/linux-insides/content/Theory/linux-theory-3.html)。


hook指针指向[malloc_hook_ini函数](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/hooks.c#L28)。


接着一个条件判断。

```cpp
// malloc.c
3033   if (__builtin_expect (hook != NULL, 0))
3034     return (*hook)(bytes, RETURN_ADDRESS (0));

```

关于`__builtin_expect`可以查阅其文档。这里表示如果hook!=NULL就调用hook所指向的函数(即malloc_hook_ini函数)并将所指向的函数的返回值返回。`RETURN_ADDRESS`的宏定义为：[RETURN_ADDRESS](https://elixir.free-electrons.com/glibc/glibc-2.31/source/include/libc-symbols.h#L207)(其含义可以参考[官方文档](https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html))。这里所传入的第一个参数是我们申请的字节(即0x512),第二个参数是`__libc_malloc`函数的返回地址(即first_filt.c main函数中`char* a = malloc(0x512);`的下一条指令)。

然后进入[malloc_hook_ini ](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/hooks.c#L28)函数。

## malloc_hook_ini函数

```cpp
27 static void *
28 malloc_hook_ini (size_t sz, const void *caller)
29 {
30   __malloc_hook = NULL;
31   ptmalloc_init ();
32   return __libc_malloc (sz);
33 }
```

### ptmalloc_init函数

进入到[ptmalloc_init函数](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/arena.c#L289)。

```cpp
288 static void
289 ptmalloc_init (void)
290 {
291   if (__malloc_initialized >= 0)
292     return;
293 
294   __malloc_initialized = 0;   

```

\__malloc_initialized全局变量用来保证ptmalloc_init函数只会被初始化一次。

接着进入

```cpp
296 #ifdef SHARED
297   /* In case this libc copy is in a non-default namespace, never use brk.
298      Likewise if dlopened from statically linked program.  */
299   Dl_info di;
300   struct link_map *l;
301 
302   if (_dl_open_hook != NULL
303       || (_dl_addr (ptmalloc_init, &di, &l, NULL) != 0
304           && l->l_ns != LM_ID_BASE))
305     __morecore = __failing_morecore;
306 #endif
```

大概就是一个关于动态链接的检查以及错误处理。没有找到关于这几段的语句的说明文档,具体可以见[源代码与注释](https://elixir.free-electrons.com/glibc/glibc-2.31/source/elf/dl-libc.c#L143)。


然后来看[下面这两句](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/arena.c#L308)在干啥。

```cpp
308   thread_arena = &main_arena;
309  
310   malloc_init_state (&main_arena);

```

thread_arena是线程独享的arena信息。这里初始化引用[main_arena](https://elixir.free-electrons.com/glibc/glibc-2.31/source/malloc/malloc.c#L1742)。

> Thread-Local Storage 可以参考[Thread-Local Storage](https://gcc.gnu.org/onlinedocs/gcc/Thread-Local.html#Thread-Local)


根据[malloc_state - heap-exploitation](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/malloc_state),malloc_stat结构描述一个arena的信息。


* [How to use \__malloc_hook?](https://stackoverflow.com/questions/11356958/how-to-use-malloc-hook)
