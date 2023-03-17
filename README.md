# HRP-Nnepnep-auto-pwn(墨河)

## 脚本知识开源声明

```
版权所有 (C) 2023，HRP 和 Nepnep战队。保留所有权利。

该脚本（以下简称“本脚本”）是一个开源的脚本，遵循 MIT 许可证（详见 LICENSE 文件）。

本脚本仅供学习和研究使用，未经 HRP 和 Nepnep战队许可，不得将本脚本用于商业目的。

在使用本脚本的过程中，您应该遵守适用的法律法规和相关规定，同时应该遵循公平使用原则，尊重他人的知识产权和合法权益。

HRP 和 Nepnep战队保留对本脚本的解释权和修改权，如有疑问或建议，请联系我们。

如果您使用了本脚本或参考了本脚本的内容，请注明脚本来源和作者，感谢您的尊重和支持。

谢谢！

HRP 和 Nepnep战队
```



## 前言

这个工具的全称是HRP-Nnepnep-auto-pwn，别称是墨河（圆我个中二病

算是补全对1.0的遗憾没有做到auto，只是生成了exp模板，现在2.0暂时我只做了对read溢出的处理，其余的溢出等我一年后再说吧，我要好好学习考研上岸去了，安全先告一段落吧。

## 功能

- [x] 绝大部分AMD64 ELF文件callback，callback支持任意用户函数开始和从任意call点位开始，一直回调到主函数，逆序输出
- [x] angr自动化逻辑判断，目前算法比较菜，而且符号执行上限太大，这个只适用于百分之30-40左右的逻辑判断情况，输入器越多分析时间越长，同理if分支越多也是，不过嘛是支持整型和字符串同判，也就是可以一起存在于if判断里面
- [x] 自动化处理read溢出(ret2backdoor,ret2libc(含ORW),栈迁移)
- [ ] 自动化处理scanf溢出
- [ ] 自动化处理gets溢出

## 安装方法

```
python 3.6.9以上环境

apt-get update
apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
pip3 install claripy
pip3 install angr
pip3 install re
pip3 install capstone

```

## 使用方法

```
python3 HRP-FUZZ-2.0.py ./filepath --callback target_addr(HEX) #指定地址回调到主函数

python3 HRP-FUZZ-2.0.py ./filepath auto #自动化分析出EXP

python3 HRP-FUZZ-2.0.py ./filepath #单独提供利用模板

```

## 结果展示

### 1.auto模式

<img width="1165" alt="1679060405878" src="https://user-images.githubusercontent.com/72968793/225921436-be12d919-55aa-4fa3-a91c-0f8a609a52dc.png">

### 2.路径回调模式

<img width="813" alt="1679060474882" src="https://user-images.githubusercontent.com/72968793/225921629-10644c5e-c90a-4cb7-b779-19e122b6d33d.png">

## 解释说明

```
1.关于ORW模板建议使用python2去执行，因为0664的open模式，但是python3不支持0开头的数

2.angr符号执行准确度问题可以调整fuzz2.py中的input_size最小值或者最大值(默认分别是10,1024,最大值在HPR-FUZZ-2.0.py里面修改)

3.执行时长问题，我个人建议单个函数内的输入变量不要超过3个，一个if内不要夹杂大于2个变量的判断，这样时间会比较正常

4.自动化获取的逻辑条件我默认是采用sendline发送，打不通自己试试看用send毕竟谁也不知道代码编写者在用strcmp是什么要求呢

5.对于更换libc自己学习patchelf就好了，这个我有空再加入（虽然也就几句代码的事情）
```

## 个人碎碎念

```
1.你说我这个工具他强吗？还真不强，那你说他有意义吗，我觉得有的，基于静态汇编分析+符号执行可以节约很多运行时间而且静态汇编特征准确度是非常高的。
2.我这玩意会是鸡肋吗？我觉得不会，对于0pwn人可以拿去试试看说不定能出exp呢？对于不会angr的可以看看我的fuzz2.py可以学习一波
（虽然但是我以后再改进是不会采用angr的了，符号执行终究上限太低）
3.我也不知道我思想是落后还是说勉勉强强，我没有任何的FUZZ基础，全是基于个人逻辑想象+GPT4.0，墨河这个脚本工具本身我的定义就是玩具。
```

