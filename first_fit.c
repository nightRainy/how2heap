#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	fprintf(stderr, "这个文件并不是一个攻击的展示demo,本文件只展示了最原始的glibc分配方法\n");
	fprintf(stderr, "glibc使用first-fit原则来选择一个free chunk.\n");
	fprintf(stderr, "如果一个chunk是被free掉且足够大的,malloc就会去选择这个chunk.\n");
	fprintf(stderr, "这个性质可以被利用在use-after-free的漏洞利用上.\n");

	fprintf(stderr, "现在分配两个buffer,这两个buffer不一定非要是fastbin,可以很大.\n");
	char* a = malloc(0x512);
	char* b = malloc(0x256);
	char* c;

	fprintf(stderr, "1st malloc(0x512): %p\n", a);
	fprintf(stderr, "2nd malloc(0x256): %p\n", b);
	fprintf(stderr, "我们可以在这继续mallocing...\n");
	fprintf(stderr, "现在让我们给a赋值为 \"this is A! \" 以供我们之后读取\n");
	strcpy(a, "this is A!");
	fprintf(stderr, "chunk a: %p 里的内容是 %s\n", a, a);

	fprintf(stderr, "现在我们free第一个chunk...\n");
	free(a);

	fprintf(stderr, "我们不需要再free其他chunk了.现在只要我们申请的内存比0x512小, 它都会在 %p 处开始\n", a);

	fprintf(stderr, "因此,现在让我们分配 0x500 字节\n");
	c = malloc(0x500);
	fprintf(stderr, "3rd malloc(0x500): %p\n", c);
	fprintf(stderr, "并且给c赋一个不同的字符串, \"this is C!\"\n");
	strcpy(c, "this is C!");
	fprintf(stderr, "chunk c: %p 的内容是 %s\n", c, c);
	fprintf(stderr, "chunk a: %p 的内容是 %s\n", a, a);
	fprintf(stderr, "可以看到此时我们再查看chunk a的时候,会发现他现在保存着来自chunk c的内容.\n");
}

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	fprintf(stderr, "This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
	fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
	fprintf(stderr, "If a chunk is free and large enough, malloc will select this chunk.\n");
	fprintf(stderr, "This can be exploited in a use-after-free situation.\n");

	fprintf(stderr, "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
	char* a = malloc(0x512);
	char* b = malloc(0x256);
	char* c;

	fprintf(stderr, "1st malloc(0x512): %p\n", a);
	fprintf(stderr, "2nd malloc(0x256): %p\n", b);
	fprintf(stderr, "we could continue mallocing here...\n");
	fprintf(stderr, "now let's put a string at a that we can read later \"this is A!\"\n");
	strcpy(a, "this is A!");
	fprintf(stderr, "first allocation %p points to %s\n", a, a);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "We don't need to free anything again. As long as we allocate smaller than 0x512, it will end up at %p\n", a);

	fprintf(stderr, "So, let's allocate 0x500 bytes\n");
	c = malloc(0x500);
	fprintf(stderr, "3rd malloc(0x500): %p\n", c);
	fprintf(stderr, "And put a different string here, \"this is C!\"\n");
	strcpy(c, "this is C!");
	fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
	fprintf(stderr, "first allocation %p points to %s\n", a, a);
	fprintf(stderr, "If we reuse the first allocation, it now holds the data from the third allocation.\n");
}
*/