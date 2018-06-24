#include<stdio.h>
void print_hello(void)
{
	printf("hello\n");
}
int main()
{
	int i;
	for (i=0;i<3;i++)
	{
		print_hello();
	}
	printf("ptrace\n");
	return 0;
}