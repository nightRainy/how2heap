> 汉化了[shellphish的how2heap项目](https://github.com/shellphish/how2heap) 最下方是原文

# 堆利用教程 

这个项目用于学习各种堆利用技术
我们在一次hack会议上提出了这个想法,如下是我们已经写了demo的利用技术:

| 文件 | 技术 | Glibc版本 |对应的ctf题目 |
|------|-----------|---------------|--------------------------|
| [first_fit.c](first_fit.c) | 演示了glibc的first fit原则. | | |
| [calc_tcache_idx.c](calc_tcache_idx.c) | 演示如何计算tcache索引的方法. | | |
| [fastbin_dup.c](fastbin_dup.c) | 通过控制fast bin free list 来欺骗malloc,从而获得一个已经分配过的堆指针 | | |
| [fastbin_dup_into_stack.c](glibc_2.25/fastbin_dup_into_stack.c) | 通过构造fast bin free list来欺骗malloc,从而获得一个指向任意地址的堆指针 | latest | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](glibc_2.25/fastbin_dup_consolidate.c) | 通过把一个指针既放到fastbin freelist中又放到unsorted bin中来欺骗malloc,从而获得一个已经分配了的堆指针 | latest | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](glibc_2.26/unsafe_unlink.c) | 利用free在一个corrupted chunk上获得任意写的能力. | < 2.26 | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](glibc_2.25/house_of_spirit.c) | 通过释放一个伪造的fastbin来获得一个指向任意地址的指针. | latest | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](glibc_2.25/poison_null_byte.c) | 利用单个空字节溢出 | < 2.26 | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb) |
| [house_of_lore.c](glibc_2.26/house_of_lore.c) | 通过伪造smallbin freelist来欺骗malloc,从而获得一个指向任意地址的指针| < 2.26 | |
| [overlapping_chunks.c](glibc_2.26/overlapping_chunks.c) | 通过溢出修改一个free 掉的 unsorted bin的size来使得新分配的chunk与已经存在的chunk产生重叠 | < 2.26 | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](glibc_2.25/overlapping_chunks_2.c) | 利用溢出漏洞修改一个正在使用的chunk的size来使得我们新分配的chunk和已经存在的chunk产生重叠  | latest | |
| [house_of_force.c](glibc_2.25/house_of_force.c) | 利用top chunk的hearder来让malloc返回一个几乎指向任意地址的内存 | < 2.29 | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](glibc_2.26/unsorted_bin_into_stack.c) | 利用溢出漏洞修改一个在unsorted bin freelist的被free掉的chunk来获得一个指向几乎任意地址的指针  | < 2.26 | |
| [unsorted_bin_attack.c](glibc_2.26/unsorted_bin_attack.c) | 利用溢出一个在unsorted bin freelist的被free掉的chunk来将一个超大的值写到任意地址  | < 2.28 | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](glibc_2.26/large_bin_attack.c) | 利用溢出一个在large bin freelist上的被Free掉的chunk来向任意地址写一个超大的值 | < 2.26 | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](glibc_2.26/house_of_einherjar.c) | 利用一个空字节溢出来欺骗malloc,从而获得一个被我们控制的指针  | < 2.26 | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_orange.c](glibc_2.25/house_of_orange.c) | 利用top chunk来获得任意代码执行的方法  | < 2.26 | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [tcache_dup.c](glibc_2.26/tcache_dup.c) | 通过控制tcache freelist来欺骗malloc,从而获得一个已经分配的堆指针 | 2.26 - 2.28 | |
| [tcache_poisoning.c](glibc_2.26/tcache_poisoning.c) | 通过控制tcache freelist来欺骗malloc从而获得一个机会指向任意地址的指针 | > 2.25  | |
| [tcache_house_of_spirit.c](glibc_2.26/tcache_house_of_spirit.c) | free一个Fake chunk来让malloc返回一个指向几乎任意地址的指针 | > 2.25 | |

GnuLibc正在不断的开发中,上面的一些利用方法已经让malloc和free的代码逻辑中引入了一致性检测
因此,这些常规检测让我们不能使用一些利用方法或者在有可能的情况下需要我们做一些调整来bypss这些检测
我们通过为每个需要调整的Glibc版本保留相同技术的多个版本来解决此问题。

结构如下: `glibc_<version>/technique.c`.

有一个很好的例子吗？
添加到这里！
尝试将整个技术内联到单个`.c`中-这样学习起来容易得多。

# 堆利用工具

有一些堆利用的工具

## shadow

jemalloc 开发框架: https://github.com/CENSUS/shadow

## libheap

在gdb中查看glibc heap: https://github.com/cloudburst/libheap

## heap-viewer

在IDA PRO中查看glibc heap: https://github.com/danigargu/heap-viewer

## heapinspect

一个基于python的可视化heap playground: https://github.com/matrix1001/heapinspect

## Malloc Playground

给定的`malloc_playground.c`文件是程序源代码，该程序提示用户一些分配和释放内存的命令。

# Other resources

一些好的堆利用的学习资源, 大致按其发布顺序如下:

- glibc in-depth tutorial (https://heap-exploitation.dhavalkapil.com/) - 书籍和利用案例
- ptmalloc fanzine, 一系列与ptmalloc上meta-data攻击有关的资源和例子 (http://tukan.farm/2016/07/26/ptmalloc-fanzine/)
- A malloc diagram, from libheap (https://raw.githubusercontent.com/cloudburst/libheap/master/heap.png)
- Glibc Adventures: The Forgotten Chunk (https://go.contextis.com/rs/140-OCV-459/images/Glibc_Adventures-The_Forgotten_Chunks.pdf) - 高级堆利用方法
- Pseudomonarchia jemallocum (http://www.phrack.org/issues/68/10.html)
- The House Of Lore: Reloaded (http://phrack.org/issues/67/8.html)
- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - some malloc exploitation techniques
- Yet another free() exploitation technique (http://phrack.org/issues/66/6.html)
- Understanding the heap by breaking it (https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) - explains heap implementation and a couple exploits
- The use of set_head to defeat the wilderness (http://phrack.org/issues/64/9.html)
- The Malloc Maleficarum (http://seclists.org/bugtraq/2005/Oct/118)
- OS X heap exploitation techniques (http://phrack.org/issues/63/5.html)
- Exploiting The Wilderness (http://seclists.org/vuln-dev/2004/Feb/25)
- Advanced Doug lea's malloc exploits (http://phrack.org/issues/61/6.html)
- GDB Enhanced Features (GEF) Heap Exploration Tools (https://gef.readthedocs.io/en/master/commands/heap/)
- Painless intro to the Linux userland heap (https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/)

# Hardening
glibc中嵌入了一些“hardening”措施, 像 `export MALLOC_CHECK_=1` (启用了一些检查), `export MALLOC_PERTURB_=1` (数据被覆盖), `export MALLOC_MMAP_THRESHOLD_=1` (始终使用mmap()), ...

更多的信息: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

There's also some tracing support as [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage), and in other functions in this family.


# Educational Heap Exploitation

This repo is for learning various heap exploitation techniques.
We came up with the idea during a hack meeting, and have implemented the following techniques:

| File | Technique | Glibc-Version |Applicable CTF Challenges |
|------|-----------|---------------|--------------------------|
| [first_fit.c](first_fit.c) | Demonstrating glibc malloc's first-fit behavior. | | |
| [calc_tcache_idx.c](calc_tcache_idx.c) | Demonstrating glibc's tcache index calculation. | | |
| [fastbin_dup.c](fastbin_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. | | |
| [fastbin_dup_into_stack.c](glibc_2.25/fastbin_dup_into_stack.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | latest | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](glibc_2.25/fastbin_dup_consolidate.c) | Tricking malloc into returning an already-allocated heap pointer by putting a pointer on both fastbin freelist and unsorted bin freelist. | latest | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](glibc_2.26/unsafe_unlink.c) | Exploiting free on a corrupted chunk to get arbitrary write. | < 2.26 | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](glibc_2.25/house_of_spirit.c) | Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer. | latest | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](glibc_2.25/poison_null_byte.c) | Exploiting a single null byte overflow. | < 2.26 | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb) |
| [house_of_lore.c](glibc_2.26/house_of_lore.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist. | < 2.26 | |
| [overlapping_chunks.c](glibc_2.26/overlapping_chunks.c) | Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk | < 2.26 | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](glibc_2.25/overlapping_chunks_2.c) | Exploit the overwrite of an in use chunk size in order to make a new allocation overlap with an existing chunk  | latest | |
| [house_of_force.c](glibc_2.25/house_of_force.c) | Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer | < 2.29 | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](glibc_2.26/unsorted_bin_into_stack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to return a nearly-arbitrary pointer.  | < 2.26 | |
| [unsorted_bin_attack.c](glibc_2.26/unsorted_bin_attack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address  | < 2.28 | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](glibc_2.26/large_bin_attack.c) | Exploiting the overwrite of a freed chunk on large bin freelist to write a large value into arbitrary address  | < 2.26 | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](glibc_2.26/house_of_einherjar.c) | Exploiting a single null byte overflow to trick malloc into returning a controlled pointer  | < 2.26 | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_orange.c](glibc_2.25/house_of_orange.c) | Exploiting the Top Chunk (Wilderness) in order to gain arbitrary code execution  | < 2.26 | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [tcache_dup.c](glibc_2.26/tcache_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the tcache freelist. | 2.26 - 2.28 | |
| [tcache_poisoning.c](glibc_2.26/tcache_poisoning.c) | Tricking malloc into returning a completely arbitrary pointer by abusing the tcache freelist. | > 2.25  | |
| [tcache_house_of_spirit.c](glibc_2.26/tcache_house_of_spirit.c) | Frees a fake chunk to get malloc to return a nearly-arbitrary pointer. | > 2.25 | |

The GnuLibc is under constant development and several of the techniques above have let to consistency checks introduced in the malloc/free logic.
Consequently, these checks regularly break some of the techniques and require adjustments to bypass them (if possible).
We address this issue by keeping multiple versions of the same technique for each Glibc-release that required an adjustment.
The structure is `glibc_<version>/technique.c`.

Have a good example?
Add it here!
Try to inline the whole technique in a single `.c` -- it's a lot easier to learn that way.

# Heap Exploitation Tools

There are some heap exploitation tools floating around.

## shadow

jemalloc exploitation framework: https://github.com/CENSUS/shadow

## libheap

Examine the glibc heap in gdb: https://github.com/cloudburst/libheap

## heap-viewer

Examine the glibc heap in IDA Pro: https://github.com/danigargu/heap-viewer

## heapinspect

A Python based heap playground with good visualization for educational purposes: https://github.com/matrix1001/heapinspect

## Malloc Playground

The `malloc_playground.c` file given is the source for a program that prompts the user for commands to allocate and free memory interactively.

# Other resources

Some good heap exploitation resources, roughly in order of their publication, are:

- glibc in-depth tutorial (https://heap-exploitation.dhavalkapil.com/) - book and exploit samples
- ptmalloc fanzine, a set of resources and examples related to meta-data attacks on ptmalloc (http://tukan.farm/2016/07/26/ptmalloc-fanzine/)
- A malloc diagram, from libheap (https://raw.githubusercontent.com/cloudburst/libheap/master/heap.png)
- Glibc Adventures: The Forgotten Chunk (https://go.contextis.com/rs/140-OCV-459/images/Glibc_Adventures-The_Forgotten_Chunks.pdf) - advanced heap exploitation
- Pseudomonarchia jemallocum (http://www.phrack.org/issues/68/10.html)
- The House Of Lore: Reloaded (http://phrack.org/issues/67/8.html)
- Malloc Des-Maleficarum (http://phrack.org/issues/66/10.html) - some malloc exploitation techniques
- Yet another free() exploitation technique (http://phrack.org/issues/66/6.html)
- Understanding the heap by breaking it (https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) - explains heap implementation and a couple exploits
- The use of set_head to defeat the wilderness (http://phrack.org/issues/64/9.html)
- The Malloc Maleficarum (http://seclists.org/bugtraq/2005/Oct/118)
- OS X heap exploitation techniques (http://phrack.org/issues/63/5.html)
- Exploiting The Wilderness (http://seclists.org/vuln-dev/2004/Feb/25)
- Advanced Doug lea's malloc exploits (http://phrack.org/issues/61/6.html)
- GDB Enhanced Features (GEF) Heap Exploration Tools (https://gef.readthedocs.io/en/master/commands/heap/)
- Painless intro to the Linux userland heap (https://sensepost.com/blog/2017/painless-intro-to-the-linux-userland-heap/)

# Hardening
There are a couple of "hardening" measures embedded in glibc, like `export MALLOC_CHECK_=1` (enables some checks), `export MALLOC_PERTURB_=1` (data is overwritten), `export MALLOC_MMAP_THRESHOLD_=1` (always use mmap()), ...

More info: [mcheck()](http://www.gnu.org/software/libc/manual/html_node/Heap-Consistency-Checking.html), [mallopt()](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html).

There's also some tracing support as [mtrace()](http://manpages.ubuntu.com/mtrace), [malloc_stats()](http://manpages.ubuntu.com/malloc_stats), [malloc_info()](http://manpages.ubuntu.com/malloc_info), [memusage](http://manpages.ubuntu.com/memusage), and in other functions in this family.

