#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <pthread.h>

#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

// CR4
#define CR4_PAE (1U << 5)

// CR0
#define CR0_PE 1u
#define CR0_PG (1U << 31)

#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

struct vm {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    char *mem;
    struct kvm_run *kvm_run;
};

struct vm_params {
    char *guestImg;
    size_t memSize;
    size_t pageSize;
};

int init_vm(struct vm *vm, size_t mem_size)
{
    struct kvm_userspace_memory_region region;
    int kvm_run_mmap_size;

    vm->kvm_fd = open("/dev/kvm", O_RDWR);
    if (vm->kvm_fd < 0) {
        perror("open /dev/kvm");
        return -1;
    }

    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        return -1;
    }

    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        perror("mmap mem");
        return -1;
    }

    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = mem_size;
    region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
    }

    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        return -1;
    }

    kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        return -1;
    }

    vm->kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        return -1;
    }

    return 0;
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
    struct kvm_segment seg = {
            .base = 0,
            .limit = 0xffffffff,
            .present = 1, // Prisutan ili učitan u memoriji
            .type = 11, // Code: execute, read, accessed
            .dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
            .db = 0, // Default size - ima vrednost 0 u long modu
            .s = 1, // Code/data tip segmenta
            .l = 1, // Long mode - 1
            .g = 1, // 4KB granularnost
    };

    sregs->cs = seg;

    seg.type = 3; // Data: read, write, accessed
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

// Omogucavanje long moda.
// Vise od long modu mozete prociati o stranicenju u glavi 5:
// https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf
// Pogledati figuru 5.1 na stranici 128.
static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs, size_t memSize, size_t pageSize)
{
    // Postavljanje 4 niva ugnjezdavanja.
    // Svaka tabela stranica ima 512 ulaza, a svaki ulaz je veličine 8B.
    // Odatle sledi da je veličina tabela stranica 4KB. Ove tabele moraju da budu poravnate na 4KB.
    uint64_t page = 0;
    uint64_t pml4_addr = 0x1000;
    uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

    uint64_t pdpt_addr = 0x2000;
    uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

    uint64_t pd_addr = 0x3000;
    uint64_t *pd = (void *)(vm->mem + pd_addr);

    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

    size_t pages = memSize / pageSize;

    switch (pageSize) {
        case 4 * 1024:
            uint64_t pt_addr = 0x4000;
            uint64_t *pt = (void *)(vm->mem + pt_addr);

            pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
            pt[0] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;

            for (size_t i = 0; i < pages; i++) {
                pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
                page += pageSize;
            }
            break;
        case 2 * 1024 * 1024:
            for (size_t i = 0; i < pages; i++) {
                pd[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
                page += pageSize;
            }
            break;
    }

    // Registar koji ukazuje na PML4 tabelu stranica. Odavde kreće mapiranje VA u PA.
    sregs->cr3  = pml4_addr;
    sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
    sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging"
    sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

    // Inicijalizacija segmenata procesora.
    setup_64bit_code_segment(sregs);
}

void *vm_thread(void *arg) {
    struct vm_params *params = (struct vm_params *)arg;
    struct vm vm;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    FILE *img;
    int ret;

    if (init_vm(&vm, params->memSize)) {
        printf("Failed to init the VM\n");
        return NULL;
    }

    if (ioctl(vm.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        return NULL;
    }

    setup_long_mode(&vm, &sregs, params->memSize, params->pageSize);

    if (ioctl(vm.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        return NULL;
    }

    memset(&regs, 0, sizeof(regs));
    regs.rflags = 2;
    regs.rip = 0;
    regs.rsp = 2 << 20;

    if (ioctl(vm.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        return NULL;
    }

    img = fopen(params->guestImg, "r");
    if (img == NULL) {
        printf("Can not open binary file: %s\n", params->guestImg);
        return NULL;
    }

    char *p = vm.mem;
    while (feof(img) == 0) {
        int r = fread(p, 1, 1024, img);
        p += r;
    }
    fclose(img);

    while (1) {
        ret = ioctl(vm.vcpu_fd, KVM_RUN, 0);
        if (ret == -1) {
            printf("KVM_RUN failed\n");
            return NULL;
        }

        switch (vm.kvm_run->exit_reason) {
            case KVM_EXIT_IO:
                if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0xE9) {
                    char *p = (char *)vm.kvm_run;
                    printf("%c", *(p + vm.kvm_run->io.data_offset));
                }
                continue;
            case KVM_EXIT_HLT:
                printf("KVM_EXIT_HLT\n");
                return NULL;
            case KVM_EXIT_INTERNAL_ERROR:
                printf("Internal error: suberror = 0x%x\n", vm.kvm_run->internal.suberror);
                return NULL;
            case KVM_EXIT_SHUTDOWN:
                printf("Shutdown\n");
                return NULL;
            default:
                printf("Exit reason: %d\n", vm.kvm_run->exit_reason);
                break;
        }
    }

    return NULL;
}


int main(int argc, char *argv[])
{
    struct vm_params *vm_params;
    pthread_t *threads;
    int vmCount = 0;
    int memSize = 0;
    int pageSize = 0;

    // parsiranje argumenata komandne linije
    if (argc < 7) {
        printf("Enter all parameters\n");
        return 1;
    }

    if (strcmp(argv[1], "--memory") == 0 || strcmp(argv[1], "-m") == 0) {
        memSize = atoi(argv[2]);
        if (memSize == 2 || memSize == 4 || memSize == 8) {
            memSize *= 1024 * 1024;
        } else {
            printf("Invalid memory size.\n");
            return 1;
        }
    } else {
        printf("Invalid argument value.\n");
        return 1;
    }

    if (strcmp(argv[3], "--page") == 0 || strcmp(argv[3], "-p") == 0) {
        pageSize = atoi(argv[4]);
        if (pageSize == 4) {
            pageSize *= 1024;
        } else if (pageSize == 2) {
            pageSize *= 1024 * 1024;
        } else {
            printf("Invalid page size.\n");
            return 1;
        }
    } else {
        printf("Invalid argument value.\n");
        return 1;
    }

    if (strcmp(argv[5], "--guest") == 0 || strcmp(argv[5], "-g") == 0) {
        vmCount = argc - 6;
        if (vmCount < 1) {
            printf("No guest images.\n");
            return 1;
        }

        threads = malloc(vmCount * sizeof(pthread_t));
        vm_params = malloc(vmCount * sizeof(struct vm_params));

        for (int i = 0; i < vmCount; i++) {
            vm_params[i].guestImg = argv[6 + i];
            vm_params[i].memSize = memSize;
            vm_params[i].pageSize = pageSize;
        }
    } else {
        printf("Invalid argument value.\n");
        return 1;
    }

    for (int i = 0; i < vmCount; i++) {
        if (pthread_create(&threads[i], NULL, vm_thread, (void *)&vm_params[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < vmCount; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(vm_params);

}
