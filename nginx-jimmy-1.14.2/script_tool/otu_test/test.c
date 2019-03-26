#include <stdio.h>
#include "hsitx2_otu.h"

int main(int argc, char **argv)
{

//        otu_key 1q2w3e4r5t6y7u89
//        otu_iv azsxdcfvgbhnjmkl

//	if(run(argv[1],"sbsconadhyosungi","szvqXnLRmVdskBwf")==0)
	if(run(argv[1],"1q2w3e4r5t6y7u89","azsxdcfvgbhnjmkl")==0)
		printf("ok\n");
	else
		printf("error\n");

	

	return 0;
}
