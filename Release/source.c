#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifndef MAP_ANON
#define MAP_ANON 0x20
#endif
#define FLAG "/home/newbie/flag"

char ban[] = "\x01\x02\x03\x04\x05\x0f\x28\x29\x2a\x2b\x2c\x2d\x80\x81\x83\x88"
             "\x89\x8a\x8b\x8c\x8e\xa0\xa1\xa2\xa3\xa8\xa9\xf6\xf7\x84\x85\xb0"
             "\xb8\xc6\xc7\xcd\xe9\xea\xeb\xff\x0f\xcb\x38\x39\x3a\x3b\x3c\x3d";
char boo[] = "\x31\xC0\x31\xDB\x31\xC9\x31\xD2\x31\xF6\x31\xFF\x31\xED\x31\xE4";
void __attribute__((noreturn)) fail(const char *err)
{
    write(STDOUT_FILENO, err, strlen(err));
    _exit(1);
}

void falloc()
{
    int fd = open(FLAG, O_RDONLY);
    if (fd < 0)
        fail("failed to open flag\n");
    if (mmap(0x3456000, 0x1000, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0) == MAP_FAILED)
        fail("failed to load flag\n");
    close(fd);
}

void *ralloc()
{
    int fd, addr;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        fail("open() Failed\n");
    if (read(fd, &addr, sizeof(addr)) <= 0)
        fail("read() Failed\n");
    addr -= addr % 0x1000;
    if (mmap(addr, 0x1000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0) == MAP_FAILED)
        fail("mmap() Failed\n");
    memset(addr, 0x90, 0x1000);
    close(fd);
    return addr;
}

void filter(char what)
{
    char *i;
    for (i = ban; *i; i++)
    {
        if (*i == what)
            fail("caught by filter!!!!!\n");
    }
}

void __attribute__((noreturn)) main()
{
    char *addr;
    int i;
    falloc();
    addr = ralloc();
    memcpy(addr, boo, 16);
    write(1, "shellcode:", 10);
    read(STDIN_FILENO, addr + 16, 0x64);
    for (i=0;i<0x64;i++)
        filter(addr[16+i]);
    mprotect(addr, 0x1000, PROT_EXEC | PROT_READ);
    ((void (*)(void))addr)();
    _exit(0);
}
