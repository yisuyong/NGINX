#include <stdio.h>
       #include <stdlib.h>

int main()
{
	char *a;

	a=(char*)malloc(sizeof(11));

	a="1234567890\0";



	printf ("test :%s\n",a);
	return 0;
}
