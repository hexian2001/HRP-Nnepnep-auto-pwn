#include<stdio.h>
void init()
{
	setbuf(stdin,0);
	setbuf(stdout,0);
}
void bug()
{
	char buf[0x10];
	int a=0;
	scanf("%d",&a);
	if(a==789)
	{
		read(0,buf,0x100);
	}
}
int main(int argc, char const *argv[])
{
	init();
	puts("WELCOME");
	bug();
	return 0;
}
