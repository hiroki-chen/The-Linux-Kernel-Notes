# The Linux Kernel Playground

Two things need to be done:

- Measure the CPU frequency using PIT?

APIC Timer initialization: PIT ok → measure how many ticks are done by APIC timer using PIT (1ms) interrupt; disable interrupt temporarily; set APIC timer and disable PIT IRQ; enable APIC timer. 

A miscellaneous garden for playing with the kernel :P. Because this is a personal note on Linux kernel, I do not give any guarantee that all the information listed here is accurate. Notice that this note will introduce some notions we have already learned in undergraduate courses, but it will give more details on the ****************implementations**************** of the kernel.

# Building the Kernel and Debugging with QEMU + GDB (NO SGX)

You may build QEMU from source by following [this tutorial](https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/emulation/building-qemu-on-ubuntu), note that you should configure QEMU build by

```bash
$ ./configure --enable-slirp
$ sudo apt install libslirp-dev -y
```

- Clone the official Linux kernel repo from [kernel.org](http://kernel.org) (or some other custom git repositories).
- `cd` to the directory. Assume we are under `./linux`.
- Install necessary dependencies via package manger.
    
    ```bash
    $ sudo apt update
    $ sudo apt upgrade
    $ sudo apt install libncurses-dev flex bison openssl libssl-dev \
                     dkms libelf-dev libudev-dev libpci-dev       \
                     libiberty-dev autoconf dwarves
    # Install qemu
    $ sudo apt install qemu qemu-system qemu-kvm libvirt-daemon-system \
                     libvirt-clients bridge-utils
    $ sudo apt install gdb
    ```
    
- Generate the configuration file for `make`.
    
    ```bash
    $ make ARCH=x86_64 x86_64_defconfig
    ```
    
    - Device drivers → Network device support → Virtio network driver `<*>`
    - Device drivers → Block devices → Virtio block driver `<*>`
    
    If you are later going to play with custom kernel modules, these changes will also be necessary/helpful:
    
    - Binary Emulations → x32 ABI for 64-bit mode, turn this OFF `[ ]`
    - (The kernel allows `sudo rmmod -f some_module`) Enable loadable modules support → Module unloading - Forced module unloading `[*]`
- Then build the kernel.
    
    ```bash
    $ make -j`nproc` bzImage
    ```
    
- The image will be located under `./linux/arch/x86_64/boot/bzImage`, and by default, the kernel is built with debug symbols and a gdb script:
    
    ```bash
    $ ls ./arch/x86_64/boot
    bzImage
    
    $ ls | grep vm                                                                                                           on git:master|…1
    vmlinux
    vmlinux-gdb.py
    # Not needed.
    vmlinux.o
    vmlinux.symvers
    ```
    
- Setup the gdb.
    
    ```bash
    $ echo "add-auto-load-safe-path ./linux/vmlinux-gdb.py" >> ~/.gdbinit
    ```
    
- Since this image is bare-metal image without any filesystem support, we need to first build a running filesystem for it. The `buildroot` project can help us on this. Details about this project can be found at [https://buildroot.org](https://buildroot.org/).
    
    ```bash
    $ cd ./linux && git clone https://git.buildroot.net/buildroot.git
    $ cd buildroot && make menuconfig
    ```
    
    Set the following options on the prompt.
    
    - Target options → Target architecture, select `x86_64`
    - Toolchain → Enable C++ support `[*]`
    - Filesystem images → ext2/3/4 root filesystem; then choose the `ext4` variant
    - Target packages → Network applications → openssh `[*]`; this helps us to later send files into the QEMU guest through SSH conveniently.
- Start QEMU. Note `-append` allows us to pass the boot parameters directly to the Linux kernel running in the QEMU VM.
    
    ```bash
    $ sudo qemu-system-x86_64 \
    	  -kernel arch/x86_64/boot/bzImage \
    	  -nographic \
    	  -drive format=raw,file=buildroot/output/images/rootfs.ext4,if=virtio \
    	  -append "root=/dev/vda console=ttyS0 nokaslr other-paras-here-if-needed" \
    	  -m 4G \
    	  -enable-kvm \
    	  -cpu host \
    	  -smp $(nproc) \
        -nic user,model=e1000e
    ```
    
- Attach gdb to the instance.
    
    ```bash
    $ sudo gdb ./linux/vmlinux
    $ (gdb) target remote :1234
    $ c # conitnues running.
    ```
    
    ![I’ve added `printk` to `cpu_idle`.](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-20_um_10.52.49_AM.png)
    
    I’ve added `printk` to `cpu_idle`.
    

## Booting Ubuntu Cloud Image in QEMU (Preliminary Steps for SGX + QEMU + GDB)

Fetch the cloud image from the website.

```bash
$ wget https://cloud-images.ubuntu.com/releases/focal/release/ubuntu-20.04-server-cloudimg-amd64.img
```

Resize the image.

```bash
$ qemu-image resize ubuntu-20.04-server-cloudimg-amd64.img +128G
```

Configure the user image.

```bash
$ touch user-data
$ cat >user-data <<EOF
#cloud-config
password: 123456
chpasswd: { expire: False }
ssh_pwauth: True
EOF
$ cloud-localds user-data.img user-data
```

Start QEMU.

```bash
$ sudo qemu-system-x86_64 \
  -drive "file=ubuntu-20.04-server-cloudimg-amd64.img,format=qcow2" \
  -drive "file=user-data.img,format=raw" \
  -enable-kvm \
  -m 2G \
  -serial mon:stdio \
  -smp 2 \
  -nographic \
  -netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no \
  -device e1000,netdev=mynet0,mac=52:55:00:d1:55:01
```

It is also possible to boot with a custom kernel by

```bash
$ sudo qemu-system-x86_64 \
  -drive "file=ubuntu-20.04-server-cloudimg-amd64.img,format=qcow2" \
  -drive "file=user-data.img,format=raw" \
  -enable-kvm \
  -m 2G \
  -cpu,host \
  -serial mon:stdio \
  -smp 2 \
  -nographic \
  -nic user,model=e1000e
	-kernel ./linux/arch/x86_64/boot/bzImage \
  -append "root=/dev/sda1 console=ttyS0"
	# -cpu host,+sgx2,+sgx-provisionkey \
	# -object memory-backend-epc,id=mem1,size=128M,prealloc=on \
	# -M sgx-epc.0.memdev=mem1,sgx-epc.0.node=0 \

[    0.000000] Linux version 5.19.0-rc8-206604-g6e7765cb477a (haobin@middleMachine) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 2
[    0.000000] Command line: root=/dev/sda1 console=ttyS0
```

![Bildschirmfoto 2022-11-20 um 3.23.43 PM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-20_um_3.23.43_PM.png)

# Developing A Loadable Kernel Module

Before reading this, make sure you have installed the following dependencies.

```bash
$ sudo apt install kmod build-essential linux-headers-`uname -r` -y
```

So what is a kernel module in Linux? Modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They could extend the functionality of the kernel *******without******* the need to reboot the whole system. However, without modules, we would probably need to revamp and reboot the whole system in order to add new functionalities. For example, when a new printer is plugged in, and the system cannot recognize it, we need to install a device driver for it, which is implemented as a loadable kernel module.

People having experience with Hackintosh must know the notion of **********************kernel extensions********************** that are installed under `/System/Library/Extensions` in Darwin. This is a similar thing as kernel module, but loading a kernel extension requires a different command called `kextload` whereas in Linux, we use `*mod` -family.

![Bildschirmfoto 2022-11-20 um 9.58.28 AM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-20_um_9.58.28_AM.png)

OK, now we are back to kernel modules. We can use the following command to check currently working modules.

```bash
$ sudo lsmod
# All modules are recorded in /proc/modules
$ cat /proc/modules | sort
ac97_bus 16384 1 snd_soc_core, Live 0xffffffffc034d000
acpi_pad 184320 0 - Live 0xffffffffc021d000
acpi_tad 16384 0 - Live 0xffffffffc0260000
acpi_thermal_rel 16384 1 int3400_thermal, Live 0xffffffffc01f2000
aesni_intel 376832 4 - Live 0xffffffffc08ff000
af_alg 32768 6 algif_hash,algif_skcipher, Live 0xffffffffc0edd000
ahci 45056 3 - Live 0xffffffffc02bb000
algif_hash 16384 1 - Live 0xffffffffc0f2d000
algif_skcipher 16384 1 - Live 0xffffffffc0eeb000
```

## Hello, Module!

The first thing first in any programming language would be to write a Hello World! program, and we do so when we start to do module programming.

Note that the module source file is written in C.

```c
/* hello.c */
#include <linux/module.h>
#include <linux/kernel.h>
```

Next we should define how modules are being initialized and cleaned up by two interfaces called `init_module` and `cleanup_module`. The function `init_module` is automatically invoked when we use the command `insmod` to register this module into the kernel, and `cleanup_module` is invoked when we unload this module. Typically, `init_module` registers some handlers for something with the kernel or replace some kernel functions with its own code (in the form of function hook) while `cleanup_module`  undoes whatever the init function does, so the module can be safely unloaded. **Since kernel 2.3.13, the entry and cleanup function can be arbitrarily named, but many people still use `init` or `cleanup` as a naming convention.**

```c
int init_module(void)
{
		printk(KERN_INFO "[+] Hello from the other side!");
		
		/* Indicates a successfull call */
		return 0;
}

void cleanup_module(void)
{
		printk(KERN_INFO "[+] Goodbye!");
}

/* Newer kernel will require this */
MODULE_LICENSE("GPL");
```

If we want to tell the kernel that we use custom function as the entry point and cleanup function, we should  `#include <linux/init.h> /* Needed for the macros */` to register them.

```c
#include <linux/init.h> /* Needed for the macros */

static int __init my_init(void)
{
		do_something();
		return 0;
}

static void __exit my_exit(void)
{
		do_something();
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
```

Finally, we can write a `Makefile` which depends on the current kernel build. Moreover, if we want to separate the module into several source files, the corresponding `Makefile` needs to be slightly modified by adding `<mod_name>-objs := source1.o source2.o source3.o`.

```makefile
obj-m += hello.o
# hello-objs := hello_source1.o hello_source2.o ...

# For debugging.
ccflags-y += -g -DDEBUG

PWD := $(CURDIR)

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Then we compile it.

```makefile
$ make
make -C /lib/modules/5.15.0-50-generic/build M=/home/haobin/linux/my_modules modules
make[1]: Entering directory '/usr/src/linux-headers-5.15.0-50-generic'
  CC [M]  /home/haobin/linux/my_modules/hello.o
  MODPOST /home/haobin/linux/my_modules/Module.symvers
  CC [M]  /home/haobin/linux/my_modules/hello.mod.o
  LD [M]  /home/haobin/linux/my_modules/hello.ko
  BTF [M] /home/haobin/linux/my_modules/hello.ko
Skipping BTF generation for /home/haobin/linux/my_modules/hello.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-5.15.0-50-generic'

$ modinfo hello.ko
filename:       /home/haobin/linux/my_modules/hello.ko
license:        GPL
srcversion:     23D2E2F79B89B5B93A19C73
depends:        
retpoline:      Y
name:           hello
vermagic:       5.15.0-50-generic SMP mod_unload modversions
```

Congratulations! We have successfully built the first kernel module, and now let us load it.

```bash
$ sudo insmod hello.ko
$ sudo lsmod | grep hello
hello                  16384  0
$ dmesg | tail -3
[2722079.581837] hello: loading out-of-tree module taints kernel.
[2722079.581915] hello: module verification failed: signature and/or required key missing - tainting kernel
[2722079.582156] [+] Hello from the other side!
```

Yes, the output is now properly logged, and if we remove the module, we shall see “Goodbye”.

```bash
$ sudo rmmod hello
$ dmesg | tail -4
[2722079.581837] hello: loading out-of-tree module taints kernel.
[2722079.581915] hello: module verification failed: signature and/or required key missing - tainting kernel
[2722079.582156] [+] Hello from the other side!
[2722205.022637] [+] Goodbye!
```

# Some Utility Functions

- We can use `printk` to log some information within function body, and there are different kernel logging levels (info, debug, warn, error, etc.). For example, we can log something when CPU is idling in `kernel/sched/idle.c`. This file is located in `include/linux` which is a macro wrapper.
    
    ```c
    void __cpuidle default_idle_call(void)
    {
      printk(KERN_INFO "I am idling!!!\n");
    
    	/* some other stuffs */
    }
    ```
    
- Memory allocations in the kernel. `linux/slab.h` provides us with `kmalloc, kzmalloc, kcalloc, vmalloc, kfree, vfree`. (use `vmalloc` for large memory allocations) There are some allocation flags to be noted:
    - `GFP_KERNEL`: In most cases we use it. Using `GFP_KERNEL` means that `kmalloc` can put the current process to sleep waiting for a page when called in low-memory situations. This cannot be used in atomic context.
    - `GFP_NOWAIT`: This flag prevents direct reclaim and IO or filesystem operations and is guaranteed to be atomic but is likely to fail under memory pressure.
    - `GFP_ATOMIC`: If you think that accessing memory reserves is justified and the kernel will be stressed unless allocation succeeds, you may use `GFP_ATOMIC`.
    - User space allocations should use either of the `GFP_USER*`.
    
    `kmalloc` is used to allocate memory spaces in the low area where memory pages are already mapped to the physical addresses, so the memory allocated is *******always******* contiguous. `vmalloc` acts similarly as `kmalloc` except that `vmalloc` always remaps the allocated memory pages to virtually contiguous range without ensuring that the physical memory is contiguous.
    
- `ioctl` is a [system call](https://en.wikipedia.org/wiki/System_call) for device-specific [input/output](https://en.wikipedia.org/wiki/Input/output) operations and other operations which cannot be expressed by regular system calls.  An `ioctl` call takes as [parameters](https://en.wikipedia.org/wiki/Parameter):
    1. an open [file descriptor](https://en.wikipedia.org/wiki/File_descriptor)
    2. a request code number
    3. an untyped [pointer](https://en.wikipedia.org/wiki/Pointer_(computer_programming)) to data (either going to the driver, coming back from the driver, or both).
    
    The [kernel](https://en.wikipedia.org/wiki/Kernel_(computer_science)) generally dispatches an `ioctl` call straight to the device driver, which can interpret the request number and data in whatever way required. ******************************This user-level interface is very important because it gives us a way to manipulate the kernel module which is exposed as a device under `/dev/*`.**
    
- Todo: Deals with exception, APIC
- Todo: process scheduler
- Todo: memory management and page fault handling
- Todo: SGX cache side channel reproduction. ⇒ We may build a docker image for the kernel?
- Todo: other kernel stuffs.

## Setting up An Environment for SGX within QEMU

Warning: Some attacks won’t work!

We recommend using QEMU as a KVM host for the debugging the SGX which does not need to change the behavior of the host machine, but an in-place modification on the host machine is also possible.

Make sure *all* of the following conditions are satisfied.

- The host machine supports SGX.
- SGX is enabled in BIOS on the host machine.
- The kernel of the **host machine** must be later than 5.13 because the KVM support for SGX has been enabled since that version.
- The kernel of the guest OS should be later than 5.11 so that we can use the out-of-the-tree kernel driver for SGX (I encountered problems when I use the built-in kernel with the cloud image). This kernel can be built from source, but make sure you have enabled kernel support for SGX. The cloud image can be found in [https://cloud-images.ubuntu.com/releases/](https://cloud-images.ubuntu.com/releases/), and you can follow the instructions in previous sections. By default, SGX2 should be enabled if the host supports it.

To play with SGX in the QEMU, we will need QEMU that supports the emulation of SGX. It is strongly recommended that you install QEMU from source. Use the following command to test whether your QEMU emulator supports SGX features. If QEMU displays BIOS, then it means the QEMU is properly installed.

```bash
$ sudo qemu-system-x86_64 -nographic -enable-kvm -cpu host,+sgx
SeaBIOS (version rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org)

iPXE (http://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+07F91160+07EF1160 CA00
                                                                               

Booting from Hard Disk...
Boot failed: could not read the boot disk

Booting from Floppy...
Boot failed: could not read the boot disk

Booting from DVD/CD...
Boot failed: Could not read from CDROM (code 0003)
Booting from ROM...
iPXE (PCI 00:03.0) starting execution...ok
iPXE initialising devices...ok
```

Or alternatively, you can check by

```bash
$ qemu-system-x86_64 -cpu help | xargs printf "%s\n" | grep sgx                                 on git:master|…3
sgx
sgx-debug
sgx-exinfo
sgx-kss
sgx-mode64
sgx-provisionkey
sgx-tokenkey
sgx1
sgx2
sgxlc
```

Then you can launch a QEMU instance with SGX enabled.

```bash
$ sudo qemu-system-x86_64 \
  -cpu host,+sgx-provisionkey,+sgx \
  -object memory-backend-epc,id=mem1,size=128M,prealloc=on \
	-M sgx-epc.0.memdev=mem1,sgx-epc.0.node=0 \
  -drive "file=$img,format=qcow2" \
  -drive "file=$user,format=raw" \
  -enable-kvm \
  -m 4G \
  -serial mon:stdio \
  -smp $(nproc) \
  -nographic \
  -nic user,model=e1000e \
  -kernel $kernel \
  -append "$boot_flags"

# You can also launch an Ubuntu instance.

Welcome to Buildroot
buildroot login: root
# dmesg | grep sgx
[    0.287816] sgx: EPC section 0x100000000-0x107ffffff
[    0.288374] sgx: [Firmware Bug]: Unable to map EPC section to online node. Fallback to the NUMA node 0.
```

If you want to play with `sgx-step`, you should follow the installation steps in the repository. [https://github.com/hiroki-chen/sgx-step-for-qemu](https://github.com/hiroki-chen/sgx-step-for-qemu)

# Introduction

Why I’m learning the kernel? This is because I’m doing system security research and may have intensive interactions with the low-level implementations of security components, which are highly dependent on the OS. The most popular OS in the academic area is, presumably, the Linux family. Hence, studying how Linux works is important to my future research and my personal technical stacks, so I started today (11/19/2022).

Before starting learning ***********[the kernel](https://www.kernel.org)* (for brevity, I use “the kernel” to refer to “the Linux/Unix kernel” in the following context unless it may cause potential ambiguity), it is required for one to have essential foundations for computer architecture and several basic CS core courses (data structures, algorithms, operating systems, etc.).

## Some Basic Concepts about the Kernel

The kernel has *six* major components, namely, process management, memory management, drivers, filesystems, networking protocols, and system calls.

### How Does the Kernel Boot?

We assume the kernel is running on X86_64 platform where there are two different memory modes, namely, the Real Mode (0 - 0xFFFFF, 1 MiB) and the Protected Mode.

********************************The first step: BIOS (or UEFI in modern computers) boots.******************************** When we push the power-on button, the CPU gets activated, and it will reset its registers as below. 

```bash
IP          0xfff0 
CS selector 0xf000
CS base     0xffff0000
```

Note that Intel 80836 only allows 16 bit memory address, which means anytime we could only use memory address from `0x0` to `0XFFFF` (64 KiB), so a better solution to fully utilizing the 1MiB memory space is partitioning it into 16 64 KiB-size memory trunks. This is why segmentation comes into play. When indexing a memory address under real mode, the physical address is calculated by `segmentation_selector * 16 + offset`. Given that the initial value of CS selector is `0xf000`, the physical address of first code snippet would be `0x10 * 0xf000 (cs selector) + 0xfff0 (IP) = 0xffff0`. By default, this area stores the BIOS code, and the CPU executes the `jmp CS:IP` instruction(a long jump) at `0xffff0000 + 0xfff0 = 0xfffffff0` to execute the BIOS code.

******************************************************The second step: BIOS starts BootLoader.****************************************************** When `CS:IP` points to `0xffff0`, BIOS starts from ROM, and it maps the 1MiB memory addresses into its components:

```c
0x00000000 - 0x000003FF - Real Mode Interrupt Vector Table
0x00000400 - 0x000004FF - BIOS Data Area
0x00000500 - 0x00007BFF - Unused
0x00007C00 - 0x00007DFF - Our Bootloader            <--- Note this
0x00007E00 - 0x0009FFFF - Unused
0x000A0000 - 0x000BFFFF - Video RAM (VRAM) Memory
0x000B0000 - 0x000B7777 - Monochrome Video Memory
0x000B8000 - 0x000BFFFF - Color Video Memory
0x000C0000 - 0x000C7FFF - Video ROM BIOS
0x000C8000 - 0x000EFFFF - BIOS Shadow Area
0x000F0000 - 0x000FFFFF - System BIOS
```

The most important parts are the Interrupt Vector Table (IVT) that already resides at the same location in memory ranging from `0x0000` to `0x03ff` and the interrupt services that resides at `0x0e05b`. The IVT has 256 vectors each of which is 4 bytes sized, consisting of `CS:IP`.

Finally, BIOS will select a booting device and execute the code at the boot sector by loading `boot.img` to `0x7c00`.

**************************************************************************************The third step: BootLoader loads the kernel.************************************************************************************** `boot.img` (512 KiB) is assembled from `boot.S` and is installed on the first sector (Master Boot Record) of the boot disk. Because the size of the first sector is quite limited, `boot.img` cannot do complicated jobs, so it only works as a trampoline that allow the system to load subsequent core image `core.img`, and `lzma_decompress.img` unpacks the Grub kernel `kernel.img` that boots the Linux kernel.

![Untitled](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Untitled.png)

This step involves switch from the real mode to the protected mode, on which we will elaborate. Memory management in Protected mode is divided into two, almost independent parts:

- Segmentation
- Paging

We first discuss segmentation and delay paging.

In the real mode, the physical address is calculated by the segment selector and the offset. In protected mode, however, memory segmentation is completely revamped. The memory is no longer divided into 64 KiB trunks. Instead, the size and location of each segment is described by an associated data structure called the *************Segment Descriptor************* stored in ***********************Global Descriptor Table*********************** (GDT). `lgdt gdt` loads the base address of the global descriptor table into the `GDTR` register consisting of the size (16 bits) and the address (32 bits) of GDT.

The algorithm for the transition from real mode into protected mode is:

- Disable older interrupts.
- Enable A20. A20 allows for addressing from `0x0` to `0xFFFFFFFF`. We can test that A20 is indeed enabled by overflow check. We write something to the range of real mode and try to access an address that will cause address overflow in read mode; if we are in protected mode, then the value must be different, but if we are in real mode, the value should be the same.
- Set up the IDT and the GDP (`/arch/x86/boot/compressed/head_*.S`).
- Set the PE bit in CR0 and enable paging (`/arch/x86/boot/compressed/head_*.S`).
- Jump to the code in protected mode.

```c
/*
 * Actual invocation sequence
 */
void go_to_protected_mode(void)
{
	/* Hook before leaving real mode, also disables interrupts */
	realmode_switch_hook();

	/* Enable the A20 gate */
	if (enable_a20()) {
		puts("A20 gate not responding, unable to boot...\n");
		die();
	}

	/* Reset coprocessor (IGNNE#) */
	reset_coprocessor();

	/* Mask all interrupts in the PIC */
	mask_all_interrupts();

	/* Actual transition to protected mode... */
	setup_idt();
	setup_gdt();
	protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
}
```

---

In UEFI mode, the physical memory address is the *same* as the virtual memory address because UEFI uses ***********identity-mapping.***********

---

************************************The fourth step: kernel initialization.************************************ This procedure is defined in `init/main.c`. Since the kernel initialization procedure does quite a lot of jobs, we focus on the most important ones.

- `INIT_TASK/set_task_stack_end_magic(&init_task);`: Initialize the #0 process, where `struct task_struct init_task = INIT_TASK(init_task)`. This is the first process that the kernel creates without `fork` or `kernel_thread`. This process is statically defined, which means this process exists before kernel is loaded into the memory. The first process initializes memory, page table, data structures, signals, scheduler, and hardware devices. When it executes to the end, it will spawn a `kernel_init` kernel process (which is transmuted into `init` by `execve`) and a `kthreadd` daemon thread.
- `trap_init`: Trap initialization. This function sets the interrupt gate for handling different kinds of traps.
- `mm_init`: Memory initialization.
    
    ```c
    // init/main.c
    /*
     * Set up kernel memory allocators
     */
    static void __init mm_init(void)
    {
        /*
         * page_ext requires contiguous pages,
         * bigger than MAX_ORDER unless SPARSEMEM.
         */
        page_ext_init_flatmem();
        mem_init();
        kmem_cache_init();
        pgtable_init();
        vmalloc_init();
        ioremap_huge_init();
        /* Should be run before the first non-init thread is created */
        init_espfix_bsp();
        /* Should be run after espfix64 is set up. */
        pti_init();
    }
    ```
    
- `sched_init`: Scheduler initialization.
- `rest_init`: Initialization for the rest components, but it is very important because it delimits user- and kernel-level and initializes #1 and #2 processes. Here, #1 process loads the `init` file (on the physical disk) and jump back to the user space by forcing `iret`.
    
    ```c
    if (ramdisk_execute_command) 
    { 
        ret = run_init_process(ramdisk_execute_command);
        ...... 
    }
    ...... 
    if (!try_to_run_init_process("/sbin/init") || 
        !try_to_run_init_process("/etc/init")  || 
        !try_to_run_init_process("/bin/init")  || 
        !try_to_run_init_process("/bin/sh")) 
       return 0;
    /* ----------------------- */
    static int run_init_process(const char *init_filename)
    { 
        argv_init[0] = init_filename; 
        return do_execve(getname_kernel(init_filename), 
                         (const char __user *const __user *)argv_init, 
                         (const char __user *const __user *)envp_init);
    }
    
    /* ----------------------- */
    void
    start_thread(struct pt_regs *regs, unsigned long new_ip, unsigned long new_sp)
    {
        set_user_gs(regs, 0);
        regs->fs  = 0;
        regs->ds  = __USER_DS;
        regs->es  = __USER_DS;
        regs->ss  = __USER_DS;
        regs->cs  = __USER_CS;
        regs->ip  = new_ip;
        regs->sp  = new_sp;
        regs->flags  = X86_EFLAGS_IF;
        force_iret();
    }
    EXPORT_SYMBOL_GPL(start_thread);
    ```
    
    The invocation chain is `rest_init -> kernel_init -> (run_init_process -> [load_elf]... -> start_thread); try_to_run_init_process`. Note that there are two `init`s. Here, the first `init` is located on the ramdisk (that is, the filesystem in the memory). If we need to access the physical devices, we will need to use the driver, and if the number of storage devices is limited, we can load the drivers into the kernel, but it makes kernel very huge. So we first create a filesystem in the memory called ramdisk for the time being because we do not need to use drivers to access memory. The `init` file on the ramdisk will load the driver to access (and when it finishes, the code is already in user space after `start_thread`) the physical storage where the true `init` file exists. Then `init` on the ramdisk starts the `init` on the physical storage that initializes the service, console, etc.
    
    The #2 thread is used to manage the kernel processes and is a daemon thread. It does the following things.
    
    - Continually check `kthread_create_list` global list. When we want  to create a kernel thread by `kernel_thread` (not created at this time!), it will first be added to this list.
    - After a new thread is detected, `kthreadd` uses `kernel_thread` to truly create the thread by the  `kthread` callback which allocates the system resource to the thread.
    - `kthreadd` invokes `schedule` to release the CPU.
    - The thread is executed by `wake_up_process` and `threadfn(data)`.
    
    The chain for kernel thread creation (not #0, #1, and #2) is `kthread_create(new_thread) -> kthreadd ->` `create_kthread ->``kernel_thread(kthread) -> allocate... -> schedule -> ... -> wake_up_process`. Note that the first three processes are created directly by `kernel_thread(thread_name)` while all the other kernel threads are created by `kthread_create`.
    

### UEFI – Unified Extensible Firmware Interfaces

UEFI is a replacement of the legacy BIOS interface; it is an *advanced* BIOS and has a standard of interfaces. With UEFI, the bootloader is able to

- Allocate memory from page tables* (yes, UEFI constructed it upon startup by `init`).
- Launch another piece of UEFI code from a file.
- Read a file from its simple filesystem.
- Interact with the devices.
- Connect to the network.
- Do some security protections.

---

*Paging in UEFI is identity-mapped, i.e., physical addresses are the same as the virtual addresses.

---

When we are in a legacy boot mode (BIOS), the bootloader is responsible for enabling the A20 gate, configuring DP and IDT, switching to protected mode, configuring page tables, and enabling the long mode (x64). UEFI firmware performs the same steps as standardized.

********************UEFI boot.******************** A legacy BIOS loads a 512 bytes flat binary blob from the MBR of the boot device into memory at physical address `0x7c00` and jumps to it, whereas UEFI loads an arbitrary sized UEFI application from a FAT partition on a GPT-partitioned boot device to some address selected at run-time, and then it calls the application’s main entry point. **The application can return control to the firmware if it finishes.**

```rust
/// Standard interface of any UEFI application.
#[entry]
fn _main(handle: uefi::Handle, mut st: SystemTable<Boot>) -> Status {
		Status::SUCCESS
}
```

UEFI will pass a `SystemTable` structure that contains pointers to all of the system’s ACPI tables, memory map, and other information relevant to an OS to the UEFI application entry.

****************UEFI functions.**************** UEFI establishes callable functions in memory which are grouped into sets called *********protocols********* discoverable by the `SystemTable`.  These protocols are *standard*. For example, we can use `open_protocol` to get a handle to the file on the filesystem.

### Filesystem

The Unix operating system design is centered on its **********filesystem********** in which *everything* is treated as file (including devices, networking interfaces, pipes, and so on). The filesystem is organized in the form of a *tree* where all the nodes of the tree, except the leaves, denote directory names. An interesting fact about the filesystem in Unix is that it will automatically associate a working directory for each process, either the current relative directory without a leading slash, or the absolute directory starting with a slash (from root).

Additionally, `.` means the current directory, and `..` represents the parent directory, but for root directory `/` , these two directory coincide.

As we know, a design philosophy of Linux kernel is that it treats ***********everything*********** as a file, so there are lots of *******virtual******* filesystems for managing these files, too, since they are not real files. Let us examine some common virtual filesystems.

- `/proc`. It's sometimes referred to as a process information pseudo-file system. Details of all the running process can be obtained by looking at the associated files in the directory for this process. The directory for a given process is named after its PID. For example, `/proc/1234` contains all the information of the process with PID 1234.  The purpose and contents of each of these files is explained below:
    - `/proc/PID/cmdline`: Command line arguments.
    - `/proc/PID/cpu`: Current and last cpu in which it was executed.
    - `/proc/PID/cwd`:Link to the current working directory.
    - `/proc/PID/environ`: Values of environment variables.
    - `/proc/PID/exe`: Link to the executable of this process./proc/PID/fdDirectory, which contains all file descriptors.
    - `/proc/PID/maps`:Memory maps to executables and library files.
    - `/proc/PID/mem`: Memory held by this process.
    - `/proc/PID/root`: Link to the root directory of this process.
    - `/proc/PID/stat`:Process status.
    - `/proc/PID/statm`: Process memory status information.
    - `/proc/PID/status`: Process status in human readable form.
    
    Example (Checking information of `systemd`):
    
    ![截屏2022-11-22 00.29.29.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/%25E6%2588%25AA%25E5%25B1%258F2022-11-22_00.29.29.png)
    
    Specially, we can use `/proc/self` to check the information of current process on the fly without knowint its assigned PID. For example:
    
    ![截屏2022-11-22 00.30.53.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/%25E6%2588%25AA%25E5%25B1%258F2022-11-22_00.30.53.png)
    
    If you `open`ed the device `/proc/self/maps`, it will print the current virtual memory mapping! (we can use it for SGX side-channels)
    

### Links

A filename included in a directory is called a file *********hard link or link.********* The same file may have
several links included in the same directory or in different ones, so it may have several filenames. However, hard links cannot:

- be created for directories as doing so would result in circular dependencies.
- be created across different filesystems.

**********************Symbolic or soft link********************** comes to rescue. One can think of it as a reference or pointer to the original file and can be created for arbitrary files and directories, even non-existing things.

### File Descriptor and Inode

Inode (Identifier Node) is the metadata for the file it manages, including:

![Bildschirmfoto 2022-11-19 um 12.23.21 PM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-19_um_12.23.21_PM.png)

while a file descriptor (`fd`, not to be confused with the “actual file on the disk”) is a handle (opaque) to the file it points, which can be seen as a data stream that is file-type-agnostic.

### Access Rights and Permission Control

Users of a file fall into three classes:

- The file owner.
- The user who belongs to the same group of the owner.
- Others.

There are also three types of access rights to the file: R/W/X. 

## Device Drivers

As aforementioned, everything in the Linux kernel is represented as a regular file, so are devices that are wrapped as a stream of bytes. However, there is a question: how do users interact with devices? For example, when the user plugs a printer in, how does she send command to and read something from the printer? Linux provides us with the option called device drivers which are exposed as regular files under `/dev.` For example the first IDE disk in the system is represented by `/dev/hda`. You can `cat` it.

```bash
$ cat /dev/hda > /dev/null
```

Linux supports three types of hardware device: character, block, and network, and a miscellaneous device.

- Character devices (`cdev`): they are read and written directly *without* buffering. the user has to create the device node or device file using **`cdev_init`**, **`cdev_add`**, **`class_create`**, and **`device_create`**.  For example, `/dev/console` and `/dev/ttyS0` (serial ports) are all character devices.
- Block devices (`bdev`): Block devices can only be written to and read from in multiples of the block size, typically 512 or 1024 bytes. Block devices are accessed via the buffer cache and may be randomly accessed, that is to say, any block can be read or written no matter where it is on the device. **Only a block device can support a mounted file system.**
- Network devices: they are abstract devices for the Unix sockets.
- Miscellaneous devices: Devices that are hard to be classified into the above three categories. The device node or device file will be *automatically* generated in misc drivers.

Device drivers are often tightly combined with *kernel modules*, and they all share the following properties:

1. They are part of the kernel.
2. They expose kernel interfaces to the user space. E.g., `ioctl`.
3. They are kernel services.
4. They are both loadable and configurable.
5. They are *******dynamic*******.

### A Mini Example for `cdev`

One of the first things the character driver needs to perform is to register a device region and itself to the system so that we can access it through `/dev/some_dev`. The necessary function for performing this task is `register_chrdev_region` in `linux/fs.h`.

```c
/* 
 * @param first the device number
 * @param count total number of contiguous device numbers
 * @param name  the device name
 *
 */
int register_chrdev_region(dev_t first, unsigned int count, char* name);
```

If we do not know which major number the device should be assigned with, we can ask the kernel to find one on the fly by `alloc_chrdev_region`.

```c
/* 
 * @brief Dynamically allocate a device region for character devices.
 *        Recommonded way.
 *
 * @param dev        the allocated major number
 * @param firstminor starting minor number
 * @param count      the number of contiguous device numbers
 * @param name       the device name
 *
 */
int alloc_chrdev_region(dev_t *dev, unsigned int firstminor,
										    unsigned int count, char *name);
```

This is sufficient. Most of the fundamental driver operations involve three important kernel data structures, called `file_operations`, `file`, and `inode`. 

- File operations: The operations are mostly in charge of implementing the system calls and are therefore, named `open`, `read`, and so on (check `linux/fs.h` for full list of the interfaces).
    - `struct module *owner`: Owner of the device. Setting it to `THIS_MODULE` would be enough.
    - `poll`: The kernel will repeated ask the device if I/O should block. If a driver leaves its poll method `NULL`, the device is assumed to be both readable and writable without blocking.
    - `ioctl`: Provides a way for the user space syscall `ioctl` to manipulate the device by sending command and arguments.
- `file`: Not to be confused with `FILE` which is an opaque pointer to the opened file. This is `struct file` which is visible only in kernel space.
- `inode`: The internal representation for the file.

The next is to register the device since we have already allocated a usable region for it. The data structure for character devices are defined in `linux/cdev.h`, named `struct cdev`.  Often `count` is one, but there are situations where it makes sense to have more than one device number correspond to a specific device. For example, some devices allow different operation mode through different device numbers, but they are internally the same device.

```c
/* We omit error handling. */
/* Prevent any use `cdev_init`. */
struct cdev *dev = cdev_alloc();
dev->ops = &fops;
cdev_add(dev, dev_num, 1);

/* 
	Here, dev is the cdev structure, num is the first device number to which
	this device responds, and count is the number of device numbers that should 
	be associated with the device.
*/

/* Then you create the device under /dev. */
/* Create a virtual file system */
sample_class = class_create(THIS_MODULE, "sample");
/* Create the inode. */
device_create (sample_class, NULL, dev_num, NULL, "sample_cdev%d",
               MINOR (sample_dev_t));

/*
	Simplified layout:
  +---------+---------+------------------+
	|         |         |                  |
	| /dev/d0 | /dev/d1 |     ...          | <- alloc_chrdev_region() <- class_create() <- device_create()
	|         |         |                  |
	+---------+---------+------------------+
	/\          
	major
*/
```

After loading the module, we can check `/proc/devices`.

![Bildschirmfoto 2022-11-21 um 5.43.14 PM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-21_um_5.43.14_PM.png)

`cdev_add` does not expose the `inode` type to the user space in `/dev`, so we may need to create one by first invoking `class_create` that creates the `sysfs` and then invoking `device_create` to get the `inode`.

### A Mini Example for `miscdevice`

First, we will need to define `file_operations` which define the interfaces for the device and the device itself that has some important properties like name, mode.

```c
static const struct file_operations fops = {
    .owner              = THIS_MODULE,
    .compat_ioctl       = hello_ioctl,
    .unlocked_ioctl     = hello_ioctl,
    .open               = hello_open,
    .release            = hello_release
};

static struct miscdevice hello_dev = {
    .minor  = MISC_DYNAMIC_MINOR,
    .name   = "hello_dev",
    .fops   = &fops,
    .mode   = S_IRUGO | S_IWUGO
};
```

Then we need to define all the interfaces which have fixed format.

- `xxx_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)`
- `xxx_release(struct inode *inode, struct file *file)`
- `xxx_open(struct inode *inode, struct file *file)`

Compile it and install the module:

```bash
$ make
$ sudo insmod hello.ko
$ dmseg | tail -5
[2758865.291840] [+] Hello from the other side!
[2758865.291955] [+] Created `hello_dev`

$ ls /dev | grep hello
hello_world
```

![Bildschirmfoto 2022-11-20 um 9.00.23 PM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-20_um_9.00.23_PM.png)

We can write a simple code snippet to verify if the device works.

```c
/* In kernel space: */
long
hello_ioctl (struct file *filep, unsigned int cmd, unsigned long arg)
{
  long retval;
  const size_t size = _IOC_SIZE (cmd);
  char *ret = (char *)(kmalloc (size + 0x10, GFP_KERNEL));
  char *buf = (char *)(kmalloc (size, GFP_KERNEL));

  printk (KERN_INFO "[+] Got hello_ioctl instruction: %d, %lu", cmd, arg);
  /* Copy some string from the user. */
  if (copy_from_user (buf, (void __user *)arg, size))
    {
      retval = -EFAULT;
      goto err;
    }

  /* Concatenate the string. */
  sprintf (ret, "Hello, %s!", buf);
  printk(KERN_INFO "[+] Concatenated %s\n", ret);

  /* Copy to the user. */
  if (copy_to_user ((void __user *)arg, ret, size + 0x10))
    {
      retval = -EFAULT;
      goto err;
    }

  retval = 0;

err:
  kfree (buf);
  kfree (ret);

  return retval;
}

/* In user space: */
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>

int main() {
    int fd = open("/dev/hello_world", O_RDWR);

    char buf[256] = "World!";

    ioctl(fd, _IOWR('L', 0, char*), buf);

    printf("Read %s\n", buf);

    return 0;
}
```

```c
$ gcc -o test ./test.c
$ ./test
Read Hello, World!!

$ dmesg | tail -5
[2760201.516000] [+] Hello from the other side!
[2760201.516058] [+] Created `hello_dev`
[2760204.900383] [+] Somebody opened me!
[2760204.900387] [+] Got hello_ioctl instruction: -1073198080, 140727707128304
[2760204.900389] [+] Concatenated Hello, World!!
```

Congratulations! We have successfully built a simple kernel module and allowed the user to interact with it.

## Concurrency

![Untitled](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Untitled%201.png)

- (Kernel) Semaphore: It is used to protect countable, but limited resources. If the resource is allocated, the counter decrements, and if the resource is released, the counter increments. The operations on the counter is protected by the spin lock. If there is an interrupt, the `EFLAGS` register will store this interrupt.
- (Kernel) Mutex: It is used to guarantee that ********************exactly one process******************** can enter the critical section.
- (Kernel) RwLock: A lock with finer granularity since it can lock read or write operations. Multiple reads do not interfere with write. Efficient when the number of reads is greater than that of writes.
- (Kernel) Preempt: the scheduler is permitted to forcibly perform a context switch on a driver or other part of the kernel during its execution when, say, the time slice for that process ends or it invokes `schedule`.
- (CPU) Atomic variable: On X86_64 platforms, when there are multiple cores that try to access the bus, the CPU locks the bus to ensure that the read-modify-write operation is atomic.
- (CPU) Spin locks: It does not change the running status of the current thread.
    
    ```bash
    while (resource_not_available) {
    		await();
    }
    ```
    
- (CPU) Per-CPU: Synchronize the L2 cache with the memory.
- (Memory) RCU (Read, Copy, Update): A [synchronization](https://en.wikipedia.org/wiki/Synchronization_(computer_science)) mechanism that avoids the use of lock primitives while multiple threads concurrently read and update elements that are linked through pointers and that belong to shared data structures. The old data is removed using GC.
- (Memory) Memory barrier/fence*:  A type of barrier instruction that causes a CPU or compiler to enforce an ordering constraint on memory operations issues before and after the barrier instruction. This instruction is useful because modern compiler and CPU will generate out-of-order machine code for optimization ends, but this confuses concurrency, so we need a memory barrier.

---

*Interestingly, this can be exploited as an attack primitive (see meltdown and spectre).

---

## I/O Models

- Blocking: It is used to describe the status of a *************single thread*************. We say this thread is ********blocking******** if it keeps waiting for the result of a function call until the callee returns the result.
- Non-blocking: We say this thread is non-********blocking******** if it sends a request to the function but does other things while waiting for the result. **It may check the callee every second (epoll/select)**. For example, the socket `read` can be non-blocking by setting a time interval. If `read` timed out, it returns `EWOULDBLOCK`.
    
    ![Bildschirmfoto 2022-11-27 um 1.50.24 PM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-27_um_1.50.24_PM.png)
    
- Synchronous: It is used to describe the status of the *combination of threads*. Say thread A is blocking until thread B returns the result to A, we call this scenario synchronous.
- Asynchronous: Before Y answers X, X leaves there and X can do other jobs. **X won't come back until Y notifies it.**
    
    ![Bildschirmfoto 2022-11-27 um 1.51.05 PM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-27_um_1.51.05_PM.png)
    
- Multiplexing: Slightly different from the notion in communication, though. In computing, I/O multiplexing refers to the concept of processing multiple I/O event from a **single event loop**, with syscalls as such poll/select. For example, a server is handling 1000 connections where there are only few active. If the server enables I/O multiplexing, it sends all 1000 connections into  `select/epoll` that returns a file descriptor that receives some data; if no connection receives data, it blocks until timeout. If we always spawn a new thread for an accepted connection, however, the context switch will incur large overhead.

```bash
+--------------------------------------+
|          SELECT listener             |   <---- Socket 188 receives data, notify it!
|                                      |   <---- Socket 21 receives data, notify it!
+--------------------------------------+
                  |
                  |
                 \ /
main thread handles active socket 21 and 188.
```

![Bildschirmfoto 2022-11-27 um 1.51.36 PM.png](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Bildschirmfoto_2022-11-27_um_1.51.36_PM.png)

- Epoll: A refined version of `select` . Epoll registers callbacks for each file descriptor so that when the status changes, the corresponding callback is activated to tell kernel which file descriptor should be checked.

## Interrupts

Interrupt is an *asynchronous* even handling mechanism. There are hardware interrupts generated by peripheral devices like disks, networking cards, or keyboards. Each device or device family has its own IRQ (Interrupt Request) by which the CPU can dispatch the request to the corresponding driver. Whereas there are also software interrupts generated by the current process. Note that hardware interrupts can break the CPU while software interrupts cannot, but the CPU can ignore some interrupts if they are *********maskable.*********

The kernel exposes `/proc/softirqs` and `/proc/interrupts` to the user space that allow us to examine the running status of the interrupts in the kernel. 

```bash
$ cat /proc/softirqs
										CPU0       CPU1       CPU2       CPU3
          HI:     276180     286764    2509097     254357
       TIMER:    1550133    1285854    1440533    1812909
      NET_TX:     102895         16         15         57
      NET_RX:        155        178        115    1619192
       BLOCK:       1713      15048     251826       1082
    IRQ_POLL:          0          0          0          0
     TASKLET:          9         63          6       2830
       SCHED:    1484942    1207449    1310735    1724911
     HRTIMER:          0          0          0          0
         RCU:     690954     685825     787447     878963

$ cat /proc/interrupts
					 CPU0       CPU1       CPU2       CPU3            
  0:         33          0          0          0      IO-APIC-edge      timer
  1:         10          0          0          0      IO-APIC-edge      i8042
  4:        325          0          0          0      IO-APIC-edge      serial
  8:          1          0          0          0      IO-APIC-edge      rtc0
  9:          0          0          0          0      IO-APIC-fasteoi   acpi
 10:          0          0          0          0      IO-APIC-fasteoi   virtio3
 40:          0          0          0          0      PCI-MSI-edge      virtio1-config
 41:   16669006          0          0          0      PCI-MSI-edge      virtio1-requests
 42:          0          0          0          0      PCI-MSI-edge      virtio2-config
 43:   59166530          0          0          0      PCI-MSI-edge      virtio2-requests
 44:          0          0          0          0      PCI-MSI-edge      virtio0-config
 45:    6689988          0          0          0      PCI-MSI-edge      virtio0-input.0
 46:          0          0          0          0      PCI-MSI-edge      virtio0-output.0
 47: 2093616484          0          0          0      PCI-MSI-edge      peth1-TxRx-0
 48:          5 2045859720          0          0      PCI-MSI-edge      peth1-TxRx-1
 49:         81          0          0          0      PCI-MSI-edge      peth1
NMI:          0          0          0          0      Non-maskable interrupts
LOC: 2936184495  965056330 1641503935 1442909354      Local timer interrupts
SPU:          0          0          0          0      Spurious interrupts
PMI:          0          0          0          0      Performance monitoring interrupts
IWI:   53775871   47387196   47737572   44243915      IRQ work interrupts
RTR:          0          0          0          0      APIC ICR read retries
RES: 1198594562  964481221  966552350  902484234      Rescheduling interrupts
CAL: 4294967071       4438  430547422  419910155      Function call interrupts
TLB: 1206563963   65932469 1378887038 1028081848      TLB shootdowns
TRM:          0          0          0          0      Thermal event interrupts
THR:          0          0          0          0      Threshold APIC interrupts
MCE:          0          0          0          0      Machine check exceptions
MCP:      65623      65623      65623      65623      Machine check polls
ERR:          0
```

## Memory Management

Resource: [https://tldp.org/LDP/tlk/mm/memory.html](https://tldp.org/LDP/tlk/mm/memory.html), [https://www.kernel.org/doc/gorman/html/understand/understand006.html](https://www.kernel.org/doc/gorman/html/understand/understand006.html), [https://docs.kernel.org/admin-guide/mm/concepts.html](https://docs.kernel.org/admin-guide/mm/concepts.html)

Memory management is the most important part in the kernel. Let us first do some recap:

- Modern kernel uses virtual memory mapping to manage the physical memory resources.
- Memory are managed in ******pages****** which have different IDs called ********************Page Framer Numbers******************** (PFNs).
- To index the data in the memory, we need to get the PFN and the offset to get the virtual memory address, and then the kernel translates the virtual address into physical addresses. In Linux, we can access the physical memory by `/dev/mem`.
    
    (⚠️Warning: Unless you are totally knowledgeable and well aware of what you are doing, do not write anything to this device *directly.*)
    
- When paging is on, linear address = virtual address; if paging is off, linear address = seg:off - seg_base + offset index by the segment registers.
- Peripheral devices share the same memory space with the kernel and application. In Linux, you can get the **physical** memory layout by `/proc/iomem`. This file shows you the current map of the system's memory for each physical device.
    
    ```bash
    $ sudo cat /proc/iomem                                                                                                                                                                                                             on git:master| o
    00000000-00000fff : Reserved
    00001000-0009dfff : System RAM
    0009e000-000fffff : Reserved
    # Omitted
    fee00000-feefffff : pnp 00:05
      fee00000-fee00fff : Local APIC
    ff000000-ffffffff : Reserved
      ff000000-ffffffff : pnp 00:06
    100000000-8987fffff : System RAM # -> ~ 30 GB
      2c6a00000-2c7a025c7 : Kernel code
      2c7c00000-2c8687fff : Kernel rodata
      2c8800000-2c8c455ff : Kernel data
      2c8f93000-2c95fffff : Kernel bss
    ```
    

### Buddy Algorithm – Management of Physical Memory

The **buddy memory allocation** technique is a memory allocation algorithm that divides memory into partitions to try to satisfy a memory request as suitably as possible. This algorithm divides the memory space into chunks whose size (the minimal size can be customized, e.g., 64 KB) is some power of 2, ranging from $2^0$ to $2^{\ell}$ where $\ell$ is the upper limit of the system. The power is called *****order*****.

The details of the algorithm are omitted. Together with the Buddy algorithm is the ****slab**** algorithm which further divides the memory chunks ***************to be allocated*************** by the Buddy (sometimes the granularity of the Buddy algorithm may be too coarse.)

The slab algorithm divides the memory chunk into **objects** (8KB each). The details of the slab algorithm run by the kernel can be checked by `/proc/slabinfo`. `libc -> slab(kmalloc and kfree)-> buddy`

### Direct Memory Access (DMA)

DMA is a feature of computer systems and allows certain hardware subsystems to access main system memory independently of the CPU. This is because some hardware subsystems cannot access some parts of the virtual memory space. Also, it prevents CPU from I/O interrupts since the memory access can be done directly by the device, saving a lot of time. Connected to the hardware bus is the DMA Controller (DMAC) that performs the direct memory access for devices. Note that although DMA does not need the CPU to translate the memory address into physical address, the CPU is still responsible to write the DMAC such that the device knows how much data should be transferred. Finally, when the data transfer is done, an interrupt will be sent from the DMAC to the CPU.

Low memory space and the physical memory is an one-to-one mapping.

### IOMMU

On modern micro processors, there is an advanced feature built atop the DMA, which is called the IOMMU. This component is capable of connecting a DMA-capable IO bus to the main memory. 

![Untitled](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Untitled%202.png)

It has following advantages compared with DMA.

- IOMMU allows for convenient allocation of ***********large memory space***********. With DMA, the device cannot allocate large chunks of the memory if the main memory is filled with a lot of memory fragments.
- Devices using DMA cannot use higher memory space due to the limitation of its addressing line while with IOMMU, the whole memory space is available for devices.
- IOMMU limits the privilege of memory pages in a similar fashion of paging mechanism, preventing some DMA attacks.

### Page Table Layout

The kernel uses four-level page tables to translate a virtual address into physical address. They are:

- Page Global Directory (PGD): defined as `pgd_t` and `pgdval_t`.
- Page Upper Directory (PUD): defined as `pud_t` and `pudval_t`.
- Page Middle Directory (PMD): defined as `pmd_t` and `pmdval_t`.
- Page Table Entry (PTE): defined as `pte_t` and `ptrval_t`.

```c
typedef unsigned long   pgdval_t;
typedef unsigned long   pudval_t;
typedef unsigned long   pmdval_t;
typedef unsigned long   pteval_t;

typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { pudval_t pud; } pud_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pteval_t pte; } pte_t;

/* Equivalent to */
typedef pgd pud*;
typedef pud pmd*;
typedef pmd pte*;
typedef pte unsigned long long*;
```

The corresponding headers can be found in `arch/x86/include/asm/pgtable_[64_]types.h`

![Untitled](The%20Linux%20Kernel%20Playground%20f1f7b0d7926f4f95bbaa2a428517b2ee/Untitled%203.png)

```c
addr: 0000000000000000000000000000000000000000101100010111000000010000
			[   RESERVED   ][  PGD  ][  PUD  ][  PMD  ][  PTE  ][  OFFSET  ]
```

Assume we are on X86_64 platform where the word length is 8 bytes, and note that the page size is 4KB, which means we will have 512 (= 2^9) entries (pointers, in fact) for page table at each level. Furthermore, the kernel will assign a Page Global Directory to each process, and we can access this filed by `struct mm_struct->pgd`.

Obviously, walking these tables is a relatively expensive operation because we need to look up at least four times, so we will need a cache to accelerate some frequent accesses, which is done by the Translation Lookaside Buffer (TLB).

### Page Table Entries

An entry describes how this page can be accessed and used; therefore, each page entry will have a set of flags that describe itself. Since the higher bits of the page entry is not used for virtual memory, the kernel can place some flag bits to the higher bits and the lower 12 bits (because they are not used when the kernel walks the page table) of each PTE, which is fairly reasonable, but a consequence is that the physical pages read from page tables have to be masked to avoid these flags being interpreted as offsets that confuse programmers. The kernel provides some constants for handling this.

- `PAGE_MASK = ~((1UL << 12) - 1)`: used to invalidate the last 12 bits (4KiB aligned).
    - `1 << 12`: `1000000000000b`
    - `1 << 12 - 1`: `000000000000b`
    - Flips all the bits: `11111...11111000000000000b`
- `__PHYSICAL_MASK = ~((1UL << 46) - 1)`: used to invalidate the reserved bits (flags) in higher bits.
- `PTE_PFN_MASK = PAGE_MASK & __PHYSICAL_MASK`: used to invalidate both the lower 12 bits and the higher flag bits.
- `PTE_FLAGS_MASK = ~PTE_PFN_MASK` : used to invalidate the `PTE_PFN_MASK` fields.

All the relevant flags can be found in the header `arch/x86/include/asm/pgtable_types.h`.

```c
#define _PAGE_BIT_PRESENT	0	/* is present */
#define _PAGE_BIT_RW		1	/* writeable */
#define _PAGE_BIT_USER		2	/* userspace addressable */
#define _PAGE_BIT_PWT		3	/* page write through */
#define _PAGE_BIT_PCD		4	/* page cache disabled */
/* Omitted. */
```

### Assigning Page Tables

As aforementioned, each process is assigned with a “top-level” page table (i.e., the PGD) that can be access by `struct mm_struct->pgd` pointer (`pgd_t*`), and the kernel creates the memory manager for each process at the beginning of its lifetime. Note this pointer contains the virtual address (i.e., starting address) of the PGB of the process rather than begin a pointer to a separate PGD entry.

Why do we embrace top-level in quotes? This is because the actual top-level page table should be a page table (although this does not exist in real implementation) that *indexes* PGD pages, but the process is able to find its PGD directly without the PGB entry! We therefore ask the question: how does it know `mm_struct->pgd`? The answer is: this is done by the help of a hardware register called `cr3`. Upon context switches, the current PGD `*current->mm->pgd` is written to `cr3`, and the TLB is flushed unless the page is global (such as kernel pages). The kernel has its own `mm_struct` called `init_mm`.

### Traversing the Page Table

The kernel provides us with a set of utility functions that eliminate the labor of page table traversal. It might be instructive to have a look at `__follow_ptr()`.

```c
static int __follow_ptr(struct mm_struct *mm, unsigned long address,
				                pte_t **ptepp, spinlock_t **ptlp) {

		pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
		
    pgd = pgd_offset(mm, address);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
        goto out;

		/* Omitted. */

out:
		return -EINVAL;
}
```

The `*_offset` family functions abstract away the boilerplate code that looks up each page table. We only need the memory manager of the current process and the virtual address of the target page. 

### Physical Page ↔ Virtual Page

The kernel uses the `struct page` to describe the metadata for a physical page (this struct is defined in `/linux/mm_types.h`). A number of functions are available for translating between addresses, page table entries and [](https://github.com/torvalds/linux/blob/v4.6/include/linux/mm_types.h#L44)`struct page`s; a key one of these is `virt_to_page`which translates a virtual kernel address to its corresponding physical page. Also, `pxx_page()` fetches the corresponding physical page at the given page table level, but it returns the physical page of the ***********next-level*********** page entry. E.g., `pud_page()` returns `struct page*` that references to `pmd*`.

## How Signals are Implemented

Signal is a very fundamental building block for the inter-process communication in the Linux kernel, so knowing how it works is also important. Without loss of generality let us explore singal on x64 platforms. You can check the source code located under `linux/arch/x86/kernel/signal.c`