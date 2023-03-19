#include<stdio.h>
void bug()
{
    char buf[0x100];
    read(0, buf, 0x300);
}
void test1()
{
    int a;
    char buf[0x30];
    read(0, buf, 0x10);
    scanf("%d", & a);
    getchar();
    if (!strcmp(buf, "HRPSS\n"))
    {
        bug();
    }
    if (a == 123)
    {
        puts("NOOOO");
    }
}
void init()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
}
int main(int argc, char const * argv[])
{
    init();
    puts("demo4");
    test1();

    return 0;
}
