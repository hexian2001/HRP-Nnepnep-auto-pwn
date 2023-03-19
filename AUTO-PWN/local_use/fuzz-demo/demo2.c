#include<stdio.h>
void bug()
{
	puts("username:");
	char buf[0x20];
	read(0,buf,0x20);
	if(!strcmp("HRPHRP",buf))
	{
		puts("password:");
		read(0,buf,0x666);
	}
}
void init()
{
	setbuf(stdin,0);
	setbuf(stdout,0);
}
int main(int argc, char const *argv[])
{
	int a;
	
		scanf("%d",&a);
		switch(a){
			case 1:printf("%s\n","i am 1" );break;
			case 2:printf("%s\n","i am 2" );break;
			case 3:bug();break;
			default:break;
		}
	
	return 0;
}