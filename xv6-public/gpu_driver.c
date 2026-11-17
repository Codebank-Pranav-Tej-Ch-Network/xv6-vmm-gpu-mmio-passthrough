#include "types.h"
#include "user.h"

#define GPU_VADDR 0x40000000 // Desired virtual address for MMIO

int main(void) {
    printf(1, "Initializing Userspace GPU Driver...\n");

    // Request the kernel to map the physical GPU to our virtual address
    if (map_mmio(GPU_VADDR) < 0) {
        printf(1, "MMIO Passthrough Failed!\n");
        exit();
    }

    // Write directly to the "Hardware" without kernel context switching
    volatile int *gpu_bar = (int *)GPU_VADDR;
    *gpu_bar = 0xDEADBEEF; // Send command to GPU

    printf(1, "Command 0x%x sent directly to hardware.\n", *gpu_bar);
    exit();
}
