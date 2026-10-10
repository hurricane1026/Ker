#include <inttypes.h>
#include <stdio.h>
#include <ker/ker.h>

int main(void)
{
    printf("ker %s\ncapabilities: 0x%" PRIx64 "\n",
           ker_version(), ker_capabilities());
    return 0;
}
