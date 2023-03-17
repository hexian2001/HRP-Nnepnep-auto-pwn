#include<stdio.h>
void bug()
{
	char buf[0x100];
	read(0,buf,0x300);
}
void test1()
{
	int a;
	char buf[0x30];
	read(0,buf,0x10);
	scanf("%d",&a);
	getchar();
	if(!strcmp(buf,"HRPSS"))
	{
		bug();
	}
	if(a==123)
	{
		puts("NOOOO");
	}
}
int main(int argc, char const *argv[])
{
	puts("demo4");
	test1();
	return 0;
}