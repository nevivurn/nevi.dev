#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) { 
	if (argc < 2) {
		return 1;
	}

	srand(atoi(argv[1]));
	printf("%d\n", rand());

	int a, c, d;
	c = rand();
	d = 0x66666667;
	a = c;
	d = ((long long int) d * a) >> 32;
	d >>= 2;
	a = c;
	a >>= 0x1f;
	d -= a;
	a = d;
	a <<= 2;
	a += d;
	a += a;
	c -= a;
	d = c;
	a = d + 0x41;
	printf("%d\n", a);
}
