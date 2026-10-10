#include <ker/checksum.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t ipv4[] = {0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
                     0x40, 0x11, 0, 0, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0, 0xc7};
    uint16_t checksum;
    if (ker_inet_checksum(ipv4, sizeof(ipv4), &checksum) < 0)
        return 1;
    memcpy(ipv4 + 10, &checksum, sizeof(checksum));
    printf("IPv4 header checksum: %02x%02x\n", ipv4[10], ipv4[11]);
    if (ker_inet_checksum(ipv4, sizeof(ipv4), &checksum) < 0 || checksum != 0)
        return 1;
    puts("IPv4 header checksum validated");
    return 0;
}
