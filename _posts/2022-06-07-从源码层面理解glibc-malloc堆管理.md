---
title: glibc malloc源码分析
lang: zh
layout: article
show_subscribe: false
tags: [linux,glibc,源码分析]

---

**未完待续...**

最开始是对堆上面的漏洞利用感兴趣。后来看到《CSAPP》中有个实验是自己[实现一个malloc](http://csapp.cs.cmu.edu/3e/labs.html),但想着自己写的没有malloc这么好,于是就想分析一下malloc的管理算法。主要是这么几个问题：

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

这里用IDA对测试代码进行调试。没有IDA的也可以用GDB(当然都需要下载源码)：[Include source code of malloc.c in gdb?](https://stackoverflow.com/questions/29955609/include-source-code-of-malloc-c-in-gdb)

调试主要是跟踪一下数据&控制流,找到malloc的入口点。

所用的glibc 版本：glibc-2.31

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


* [How to use \__malloc_hook?](https://stackoverflow.com/questions/11356958/how-to-use-malloc-hook)
