#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "这是一个利用fastbin进行的简单的double-free的攻击demo.\n");

	fprintf(stderr, "分配3个buffer.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "现在Free第一个chunk...\n");
	free(a);

	fprintf(stderr, "此时如果我们再一次free chunk1 : %p , 程序就会crash,因为chunk1: %p 在free-list的顶部.\n", a, a);
	// free(a);

	fprintf(stderr, "因此,我们free chunk2 %p.\n", b);
	free(b);

	fprintf(stderr, "现在我们再free chunk1: %p , 因为他现在已经不在free-list的顶部了.\n", a);
	free(a);

	fprintf(stderr, "现在的free-list是 [ %p, %p, %p ]. 如果我们再 malloc 3 次, 我们就会得到 chunk1: %p 两次!\n", a, b, a, a);
	fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));
}
/*
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

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

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));
}
*/