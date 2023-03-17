#include<stdio.h>
#include <math.h>
#include <stdio.h>
#include<unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
void sandbox(){
  struct sock_filter filter[] = {
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4),
  BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,2),
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
  BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
  BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
  BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
  .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
  .filter = filter,
  };
  prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
  prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}
void bug()
{
  char buf[0x10];
  read(0,buf,0x100);
}
void maybe()
{
  puts("123123");
  bug();
}
void a1()
{
  int sb3,sb1;
  char buf[123];
  scanf("%d",&sb1);
  read(0,buf,123);
  scanf("%d",&sb3);
  if(sb3<-567)
  {
    a2();
  }
  
}
void a2()
{
  a1();

}
int main(int argc, char const *argv[])
{
  a1();
  return 0;
}