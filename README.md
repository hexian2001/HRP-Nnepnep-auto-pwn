# 基于pwntools的有限特征fuzz和简单rop利用工具

# 引言

```
做这个东西开始是为了当做软工作业的，但是写着写着发现挺有意思的，虽然后续想要再提高准确率和容纳更多特征，可能要整个项目

推倒重来，但是目前来看这个逻辑思想还是可以的，适用于常规AMD64 CTF PWN ，I386的我是没兴趣做了，太复杂的，汇编特征不稳定，凭我一个人的精力是没可能的。
```

# 原理

```
第一步 利用pwntools查找限定函数，查找到后赋值到变量。

下一步进行的就是fuzz比对，先判断程序编译的系统版本，分为18or16和20两大类型

然后用pwntools的search查询call指令的特征0XE8存在的地址把他们全部加入到数组，并且提取出此时call的相对地址

下一步，把限定函数的地址与数组里面的地址进行公式校验，得出fuzz地址 用这个地址和call的相对地址比对，比对成功就是证明此处call的是该限定函数，具体解释去看脚本内注释

下一步，检查该限定函数是否在危险函数定义分支里面，是的话则做出相对应的检测操作，返回相关数据到用户屏幕

最后，如果存在后门和溢出，再分别进行利用判断，满足条件给出建议性EXP（这里后续会扩展多种模板利用EXP）
```

# 功能

功能一:可检测函数列表如下，用户可以自定义增加，源码不复杂。

```
read_addr=0
gets_addr=0
puts_addr=0
printf_addr=0
strcpy_addr=0
scanf_addr=0
free_addr=0
malloc_addr=0
atoi_addr=0
strncpy_addr=0
system_addr=0
syscall_addr=0
execve_addr=0
write_addr=0
mmap_addr=0
```

功能二:提供危险函数检测，列表如下

```
read 溢出:常规溢出，栈迁移，堆相关的off by null
gets 检测到就定义为溢出
printf 检测格式化字符串
strcpy 检测rsi是否大于rdi
scanf 检测是否有%s字符串被scanf调用，有则为溢出
free 检测uaf
strncpy 检测rdx是否大于rdi
system 查看各自危险调用以及参数是否可控
syscall 查看系统调用号并且给出相对应的函数
execve 同system
mmap 查询长度 地址 权限
```

功能三:自动化生成EXP模板，列表如下

```
1.read常规溢出rop，未开启pie canary 提供puts write2种模板
2.栈迁移 getshell利用 未开启 pie canary

关于模板的讲解：
这个只是一个模板，注意，注意，注意！
原来就是在检测到的溢出点上进行的EXP自动化生成，如何到达溢出点以及是否能成功达到预期效果最终都还需要用户亲自调试尝试，模板的作用在于节省时间，抵制小作文题目。模板准确率和利用率我个人认为是不算低的，当然，仅供参考，还是希望各位如果有需求的师傅如果用了模板打不通可以自己在脚本gdb动调下
```

# 未来应该能实现的功能

```
1.沙盒通防
2.多种栈溢出下的orw模板
3.给出格式化字符串漏洞利用模板
```



# 环境需求

 运行需要依赖pwntools,numpy和python2

 pwntools https://github.com/Gallopsled/pwntools

pip install numpy

# 运行脚本命令

```
python2 fuzz.py ./binary_name
```

