#include <stdint.h>
#include <stddef.h>  // Include this header for size_t
#include <string.h>

#define PORTE9 0xE9
#define PORT278 0x0278

#define OPEN 0x01
#define CLOSE 0x02
#define WRITE 0x03
#define READ 0x04


static void outb(uint16_t port, uint8_t value) {
    asm volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static uint32_t open_file(const char *filename, const char* privileges) {
    outb(PORT278, OPEN);
    while (*filename) {
        outb(PORT278, *filename++);
    }
    outb(PORT278, '\0');

    while (*privileges) {
        outb(PORT278, *privileges++);
    }
    outb(PORT278, '\0');

    return inb(PORT278);
}

static void write_file(uint32_t fd, const char *content) {
    outb(PORT278, WRITE);
    outb(PORTE9, fd+'0');
    outb(PORT278, fd);
    outb(PORT278,'\0');
    while (*content) {
        outb(PORT278, *content++);
    }
    outb(PORT278, '\0');
}

static void read_file(uint32_t fd, char *buffer, size_t size) {
    outb(PORT278, READ);
    outb(PORT278, fd + '0');
    for (size_t i = 0; i < size - 1; i++) {
        buffer[i] = inb(PORT278);
        if (buffer[i] == '\0') break;
    }
    buffer[size - 1] = '\0';
}

static void close_file(uint32_t fd) {
    outb(PORT278, CLOSE);
    outb(PORT278, fd + '0');
}

void __attribute__((noreturn)) __attribute__((section(".start"))) _start(void) {
    const char *filename = "test.txt";
    const char* privileges = "w+";
    const char *content = "guest1\n";

    char buffer[32];

    uint32_t fd = open_file(filename, privileges);
    write_file(fd, content);
    read_file(fd, buffer, sizeof(buffer));

    /*while (*str) {
        outb(PORTE9, *str++);
    }*/

    close_file(fd);

    for (;;) {
        asm volatile ("hlt");
    }
}