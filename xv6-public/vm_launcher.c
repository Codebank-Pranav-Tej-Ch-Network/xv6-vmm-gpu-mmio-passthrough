#include "types.h"
#include "user.h"

#define GPU_VADDR 0x40000000

int main(void) {
    printf(1, "Starting VM Launcher...\n");

    if (map_mmio(GPU_VADDR) < 0) {
        printf(1, "MMIO Passthrough Failed!\n");
        exit();
    }

    vm_enter();

    int up = uptime();

    volatile int *gpu_bar = (int *)GPU_VADDR;
    *gpu_bar = 0xDEADBEEF;

    printf(1, "Uptime: %d\n", up);
    printf(1, "Command 0x%x sent directly to hardware.\n", *gpu_bar);
    exit();
}
