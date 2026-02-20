/// mini-vmm: 极简 x86_64 Linux VMM
/// 
/* 物理地址          大小        内容
─────────────────────────────────────────────────────
0x0000_0000  ┌──────────────────────────────────────┐
             │  实模式中断向量表 IVT (1KB)            │
0x0000_0400  ├──────────────────────────────────────┤
             │  BIOS Data Area (256B)               │
0x0000_0500  ├──────────────────────────────────────┤
             │                                      │
             │  （空闲）                             │
             │                                      │
0x0000_7000  ├──────────────────────────────────────┤ ← ZERO_PAGE
             │  Linux Boot Protocol zero_page (4KB) │
             │  包含 boot_params 结构体              │
             │  (内存布局、cmdline地址、initrd信息等) │
0x0000_8000  ├──────────────────────────────────────┤
             │                                      │
             │  （空闲）                             │
             │                                      │
0x0001_0000  ├──────────────────────────────────────┤ ← PML4_ADDR
             │  PML4 页表 (4KB, 512 × 8B)            │
             │  [0]: PDPT_ADDR | 0x03               │
             │  [1~511]: 空                         │
0x0001_1000  ├──────────────────────────────────────┤ ← PDPT_ADDR
             │  PDPT 页表 (4KB, 512 × 8B)            │
             │  [0]: PD_BASE+0x0000 | 0x03  → 1st PD │
             │  [1]: PD_BASE+0x1000 | 0x03  → 2nd PD │
             │  [2]: PD_BASE+0x2000 | 0x03  → 3rd PD │
             │  [3]: PD_BASE+0x3000 | 0x03  → 4th PD │
             │  [4~511]: 空                          │
0x0001_2000  ├───────────────────────────────────────┤ ← PD_BASE (PD[0])
             │  PD[0] (4KB, 512 × 8B)                │
             │  [0]:   0x0000_0000 | 0x83  (2MB页)   │
             │  [1]:   0x0020_0000 | 0x83  (2MB页)   │
             │  ...                                  │
             │  [511]: 0x3FE0_0000 | 0x83  (2MB页)   │
             │  覆盖物理地址 0x0000_0000~0x3FFF_FFFF  │
0x0001_3000  ├───────────────────────────────────────┤ ← PD_BASE+0x1000 (PD[1])
             │  PD[1] (4KB)                          │
             │  覆盖物理地址 0x4000_0000~0x7FFF_FFFF  │
0x0001_4000  ├───────────────────────────────────────┤ ← PD_BASE+0x2000 (PD[2])
             │  PD[2] (4KB)                          │
             │  覆盖物理地址 0x8000_0000~0xBFFF_FFFF  │
0x0001_5000  ├───────────────────────────────────────┤ ← PD_BASE+0x3000 (PD[3])
             │  PD[3] (4KB)                          │
             │  覆盖物理地址 0xC000_0000~0xFFFF_FFFF  │
0x0001_6000  ├───────────────────────────────────────┤
             │                                       │
             │  （空闲区域）                          │
             │                                       │
0x0002_0000  ├───────────────────────────────────────┤ ← CMDLINE_ADDR
             │  内核命令行字符串 (最大 4KB)            │
             │  e.g. "console=ttyS0 reboot=k ..."    │
0x0002_1000  ├───────────────────────────────────────┤
             │                                       │
             │  （空闲区域）                          │
             │                                       │
0x0009_fc00  ├───────────────────────────────────────┤ ← EBDA_START
             │  EBDA 扩展BIOS数据区 (1KB)             │
0x000A_0000  ├───────────────────────────────────────┤
             │  VGA / Legacy ROM 区域 (384KB)         │
             │  （VMM 通常不映射，保留空洞）            │
0x000F_FFFF  ├───────────────────────────────────────┤
             │                                       │
             │  低端可用内存区域                       │
             │  （内核 vmlinux 通常加载在 0x100000）   │
             │                                       │
0x0800_0000  ├───────────────────────────────────────┤ ← INITRD_ADDR
             │  initrd 初始内存盘镜像                 │
             │  （大小不定）                          │
             ├───────────────────────────────────────┤
             │                                       │
             │  （其余可用内存）                      │
             │                                       │
0x1000_0000  └───────────────────────────────────────┘ ← 256MB 物理内存上限
*/
/// 
///
/// 修复 TSC unstable 导致 100% CPU 的问题：
///  1. 修正 CPUID：设置 KVM_CPUID_FEATURES leaf，让内核知道这是 KVM 虚机
///               并设置 KVM_FEATURE_CLOCKSOURCE2 / CLOCKSOURCE，内核优先
///               使用 kvmclock 而不是 PIT 校准 TSC
///  2. 设置 CPUID leaf 0x40000001 的 KVM feature bits
///  3. PIT ch2 模拟：让 bit5 在每次读时翻转，使 native_calibrate_cpu()
///     的 "等待 PIT 边沿" 循环能正常退出（作为保底）
///  4. 移除 cmdline 里的 clocksource=tsc / tsc=reliable，
///     改用 kvmclock（更正确），并加 no_timer_check

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use kvm_bindings::{kvm_cpuid_entry2, kvm_regs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use linux_loader::loader::elf::Elf;
use linux_loader::loader::KernelLoader;

// ─── 物理内存布局 ─────────────────────────────────────────────────────────────
const GUEST_MEM_SIZE: usize = 256 * 1024 * 1024;

const ZERO_PAGE:    GuestAddress = GuestAddress(0x0000_7000);
const PML4_ADDR:    u64 = 0x0001_0000;
const PDPT_ADDR:    u64 = 0x0001_1000;
const PD_BASE:      u64 = 0x0001_2000;
const CMDLINE_ADDR: GuestAddress = GuestAddress(0x0002_0000);
const INITRD_ADDR:  GuestAddress = GuestAddress(0x0800_0000);
const EBDA_START:   u64 = 0x0009_fc00;

// KVM CPUID leaf
const KVM_CPUID_SIGNATURE:  u32 = 0x4000_0000;
const KVM_CPUID_FEATURES:   u32 = 0x4000_0001;
// KVM feature bits (CPUID 0x40000001 EAX)
const KVM_FEATURE_CLOCKSOURCE:    u32 = 1 << 0;
const KVM_FEATURE_CLOCKSOURCE2:   u32 = 1 << 3;
const KVM_FEATURE_ASYNC_PF:       u32 = 1 << 4;
const KVM_FEATURE_STEAL_TIME:     u32 = 1 << 5;
const KVM_FEATURE_PV_EOI:         u32 = 1 << 6;
const KVM_FEATURE_CLOCKSOURCE_STABLE_BIT: u32 = 1 << 24;

// ─── 参数解析 ─────────────────────────────────────────────────────────────────

struct Config {
    kernel:   PathBuf,
    initrd:   Option<PathBuf>,
    cmdline:  String,
    mem_size: usize,
}

impl Config {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let mut kernel  = None;
        let mut initrd  = None;
        // 使用 kvmclock 作为时钟源（KVM 虚机的正确选择）
        // no_timer_check: 跳过定时器频率检查
        // lpj=: loops_per_jiffy 固定值，跳过 calibrate_delay 中的 PIT 等待
        let mut cmdline = String::from(
            "console=ttyS0,115200 earlyprintk=ttyS0,115200 \
             noapic nolapic pci=off nomodules panic=-1 \
             no_timer_check lpj=1000000",
        );
        let mut mem_size = GUEST_MEM_SIZE;
        let mut i = 1usize;
        while i < args.len() {
            match args[i].as_str() {
                "--kernel"  | "-k" => { i += 1; kernel  = Some(PathBuf::from(&args[i])); }
                "--initrd"  | "-r" => { i += 1; initrd  = Some(PathBuf::from(&args[i])); }
                "--cmdline" | "-c" => { i += 1; cmdline = args[i].clone(); }
                "--mem"     | "-m" => {
                    i += 1;
                    mem_size = args[i].parse::<usize>().expect("需要整数(MB)") << 20;
                }
                _ => {}
            }
            i += 1;
        }
        Config {
            kernel: kernel.expect("必须通过 --kernel 指定 vmlinux"),
            initrd,
            cmdline,
            mem_size,
        }
    }
}

// ─── CPUID 设置 ───────────────────────────────────────────────────────────────
//
// 关键：在 KVM hypervisor leaf (0x40000001) 中设置 clocksource feature bits，
// 让内核知道可以用 kvmclock，从而跳过 PIT 校准。

fn setup_cpuid(kvm: &Kvm, vcpu: &kvm_ioctls::VcpuFd) {
    let mut cpuid = kvm
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .expect("get_supported_cpuid 失败");

    let entries = cpuid.as_mut_slice();

    for entry in entries.iter_mut() {
        match entry.function {
            // leaf 1: 设置 hypervisor present bit (ECX bit31)
            0x1 => {
                entry.ecx |= 1 << 31; // HYPERVISOR
            }
            // KVM signature leaf: 返回 "KVMKVMKVM\0"
            KVM_CPUID_SIGNATURE => {
                entry.eax = KVM_CPUID_FEATURES; // 最大 KVM leaf
                entry.ebx = 0x4b4d564b;         // "KVMK"
                entry.ecx = 0x564b4d56;         // "VKMV"
                entry.edx = 0x0000004d;         // "M\0\0\0"
            }
            // KVM feature leaf: 告知支持的 paravirt 特性
            KVM_CPUID_FEATURES => {
                entry.eax = KVM_FEATURE_CLOCKSOURCE
                    | KVM_FEATURE_CLOCKSOURCE2
                    | KVM_FEATURE_CLOCKSOURCE_STABLE_BIT;
                entry.ebx = 0;
                entry.ecx = 0;
                entry.edx = 0;
            }
            _ => {}
        }
    }

    // 如果没有找到 KVM_CPUID_SIGNATURE / FEATURES 条目，手动添加
    // （部分 KVM 版本不自动包含这些 leaf）
    let has_sig = entries.iter().any(|e| e.function == KVM_CPUID_SIGNATURE);
    let entries_vec: Vec<kvm_cpuid_entry2> = {
        let mut v: Vec<kvm_cpuid_entry2> = entries.to_vec();
        if !has_sig {
            v.push(kvm_cpuid_entry2 {
                function: KVM_CPUID_SIGNATURE,
                index: 0, flags: 0,
                eax: KVM_CPUID_FEATURES,
                ebx: 0x4b4d564b,
                ecx: 0x564b4d56,
                edx: 0x0000004d,
                ..Default::default()
            });
            v.push(kvm_cpuid_entry2 {
                function: KVM_CPUID_FEATURES,
                index: 0, flags: 0,
                eax: KVM_FEATURE_CLOCKSOURCE
                    | KVM_FEATURE_CLOCKSOURCE2
                    | KVM_FEATURE_CLOCKSOURCE_STABLE_BIT,
                ebx: 0, ecx: 0, edx: 0,
                ..Default::default()
            });
        }
        v
    };

    // 重新构建 CpuId 并设置
    let mut new_cpuid = kvm_bindings::CpuId::new(entries_vec.len())
        .expect("CpuId::new 失败");
    for (dst, src) in new_cpuid.as_mut_slice().iter_mut().zip(entries_vec.iter()) {
        *dst = *src;
    }
    vcpu.set_cpuid2(&new_cpuid).expect("set_cpuid2 失败");
}

// ─── IO 设备 ──────────────────────────────────────────────────────────────────

struct IoDevices {
    serial_lcr: u8,
    serial_ier: u8,
    cmos_index: u8,
    pci_addr:   u32,

    // PIT ch2 模拟：让 port 0x61 的 bit5 每次读时翻转
    // native_calibrate_cpu 等一个从 0→1 的跳变，翻转后即可退出
    pit_ch2_out: bool,
    // 记录写入 0x43 的控制字，判断是否在做 ch2 gate 操作
    pit_ch2_gate: bool,
}

impl IoDevices {
    fn new() -> Self {
        IoDevices {
            serial_lcr: 0,
            serial_ier: 0,
            cmos_index: 0,
            pci_addr: 0,
            pit_ch2_out: false,
            pit_ch2_gate: false,
        }
    }

    fn write(&mut self, port: u16, data: &[u8]) {
        let v = data[0];
        match port {
            // UART COM1
            0x3F8 => {
                if self.serial_lcr & 0x80 == 0 {
                    print!("{}", v as char);
                    let _ = io::stdout().flush();
                }
            }
            0x3F9 => self.serial_ier = v,
            0x3FB => self.serial_lcr = v,
            0x3F8..=0x3FF => {}

            // PIT
            0x43 => {
                // 控制字 bit7:6 = channel, bit4:3 = access, bit2:1 = mode
                // ch2 控制字 = 0b10xxxxxx
                // gate 控制通过 port 0x61 bit0 来做，这里不处理
            }
            0x40 | 0x41 | 0x42 => {}

            // Port 0x61: bit0 控制 PIT ch2 gate
            0x61 => {
                self.pit_ch2_gate = v & 0x01 != 0;
                if self.pit_ch2_gate {
                    // gate 打开时，ch2 开始计数，输出开始变化
                    self.pit_ch2_out = false; // 从低开始
                }
            }

            // 8042
            0x60 | 0x64 => {}

            // CMOS
            0x70 => self.cmos_index = v & 0x7f,
            0x71 => {}

            // PCI
            0xCF8 => {
                if data.len() == 4 {
                    self.pci_addr = u32::from_le_bytes([
                        data[0], data.get(1).copied().unwrap_or(0),
                        data.get(2).copied().unwrap_or(0),
                        data.get(3).copied().unwrap_or(0),
                    ]);
                } else {
                    self.pci_addr = v as u32;
                }
            }
            0xCF9..=0xCFF => {}

            // PIC
            0x20 | 0x21 | 0xA0 | 0xA1 => {}

            // 其他
            0x80 | 0x92 => {}
            _ => {}
        }
    }

    fn read(&mut self, port: u16, data: &mut [u8]) {
        match port {
            // UART COM1
            0x3F8 => { for b in data.iter_mut() { *b = 0x00; } }
            0x3F9 => { for b in data.iter_mut() { *b = self.serial_ier; } }
            0x3FA => { for b in data.iter_mut() { *b = 0x01; } } // IIR: no interrupt
            0x3FB => { for b in data.iter_mut() { *b = self.serial_lcr; } }
            0x3FC => { for b in data.iter_mut() { *b = 0x00; } }
            0x3FD => { for b in data.iter_mut() { *b = 0x60; } } // LSR: TX empty
            0x3FE => { for b in data.iter_mut() { *b = 0xB0; } } // MSR: CTS+DSR+DCD
            0x3FF => { for b in data.iter_mut() { *b = 0x00; } }

            // PIT 读回
            0x40 | 0x41 | 0x42 => { for b in data.iter_mut() { *b = 0x00; } }

            // Port 0x61: NMI / PIT ch2 状态
            // bit5 = PIT ch2 output
            // 每次读时翻转 bit5，让内核的 "等待边沿" 循环可以退出
            0x61 => {
                self.pit_ch2_out = !self.pit_ch2_out;
                let val = if self.pit_ch2_out { 0x20u8 } else { 0x00u8 };
                for b in data.iter_mut() { *b = val; }
            }

            // 8042 状态：输入缓冲空(bit1=0)，输出缓冲空(bit0=0)
            0x60 => { for b in data.iter_mut() { *b = 0x00; } }
            0x64 => { for b in data.iter_mut() { *b = 0x00; } }

            // CMOS
            0x70 => { for b in data.iter_mut() { *b = self.cmos_index; } }
            0x71 => {
                let val = match self.cmos_index {
                    0x0a => 0x00, // Status A: UIP=0
                    0x0b => 0x02, // Status B: 24h
                    0x0d => 0x80, // Status D: VRT=1
                    _    => 0x00,
                };
                for b in data.iter_mut() { *b = val; }
            }

            // PCI
            0xCF8 => {
                let bytes = self.pci_addr.to_le_bytes();
                for (i, b) in data.iter_mut().enumerate() {
                    *b = bytes.get(i).copied().unwrap_or(0);
                }
            }
            0xCFC..=0xCFF => { for b in data.iter_mut() { *b = 0xFF; } }

            // PIC
            0x20 | 0xA0 => { for b in data.iter_mut() { *b = 0x00; } }
            0x21 | 0xA1 => { for b in data.iter_mut() { *b = 0xFF; } } // all masked

            // 其余：0xFF = 无设备
            _ => { for b in data.iter_mut() { *b = 0xFF; } }
        }
    }
}

// ─── 页表 ─────────────────────────────────────────────────────────────────────

fn setup_page_tables(mem: &GuestMemoryMmap) {
    mem.write_obj(PDPT_ADDR | 0x03u64, GuestAddress(PML4_ADDR)).unwrap();
    for i in 0..4u64 {
        mem.write_obj(
            (PD_BASE + i * 0x1000) | 0x03u64,
            GuestAddress(PDPT_ADDR + i * 8),
        ).unwrap();
        for j in 0..512u64 {
            mem.write_obj(
                ((i << 30) | (j << 21)) | 0x83u64,
                GuestAddress(PD_BASE + i * 0x1000 + j * 8),
            ).unwrap();
        }
    }
}

// ─── 段寄存器 / 控制寄存器 ────────────────────────────────────────────────────

fn setup_sregs(vcpu: &kvm_ioctls::VcpuFd) {
    let mut sregs = vcpu.get_sregs().unwrap();

    // selector: 0x08,   // GDT 第 1 个描述符（index=1, TI=0, RPL=0）
    // type_: 0x0b,      // 1011 = 可执行、可读、已访问（Code Segment）
    // s: 1,             // 非系统段（普通代码/数据段）
    // l: 1,             // ← 64位模式的关键！Long Mode
    // db: 0,            // l=1 时 db 必须为 0
    // dpl: 0,           // Ring 0（内核态）
    // present: 1,       // 段存在
    // g: 1,             // 粒度=4KB，limit 单位是页
    // limit: 0xffff_ffff // 4GB 段长
    let cs = kvm_bindings::kvm_segment {
        base: 0, limit: 0xffff_ffff, selector: 0x08,
        type_: 0x0b, present: 1, dpl: 0, db: 0, s: 1, l: 1, g: 1, avl: 0,
        ..Default::default()
    };

    // selector: 0x10,   // GDT 第 2 个描述符（index=2）
    // type_: 0x03,      // 0011 = 可读写、已访问（Data Segment）
    // s: 1,             // 非系统段
    // db: 1,            // 32位默认操作数大小（数据段用 db，不用 l）
    // l: 0,
    // dpl: 0,           // Ring 0
    // g: 1, present: 1
    let ds = kvm_bindings::kvm_segment {
        base: 0, limit: 0xffff_ffff, selector: 0x10,
        type_: 0x03, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0,
        ..Default::default()
    };
    sregs.cs = cs;
    sregs.ds = ds; sregs.es = ds; sregs.fs = ds; sregs.gs = ds; sregs.ss = ds;
    sregs.cr3  = PML4_ADDR;

    /*
    ### CR0 = `0x8005_0033`（1000 0000 0000 0101 0000 0000 0011 0011）
    | 位 | 名称 | 值 | 含义 |
    |----|----|---|------|
    | 31 | PG | 1 | **开启分页** |
    | 18 | AM | 1 | 对齐检查掩码 |
    | 16 | WP | 1 | 写保护（Ring0不能写只读页）|
    | 5  | NE | 1 | x87 异常本地处理 |
    | 4  | ET | 1 | 扩展类型（固定为1）|
    | 1  | MP | 1 | 监控协处理器 |
    | 0  | PE | 1 | **开启保护模式** |
    PE=1 + PG=1 是进入保护/分页模式的两个核心开关。
    ---
    */
    sregs.cr0  = 0x8005_0033;

    /*
    ### CR4 = `0x0000_02a0` (0010 1010 0000)
    | 位 | 名称 | 值 | 含义 |
    |----|----|----|------|
    | 9  | OSFXSR | 1 | 支持 SSE 指令 |
    | 7  | PGE    | 1 | 页全局使能（TLB 优化）|
    | 5  | PAE    | 1 | **物理地址扩展**，Long Mode 必须开启 |

    PAE=1 是启用 64 位分页（PML4）的前提条件。
    ---
    */
    sregs.cr4  = 0x0000_02a0;

    /*
    ### EFER = `0x0501` （0101 0000 0001）

    EFER 是 MSR 寄存器（`0xC000_0080`），控制 Long Mode：

    | 位 | 名称 | 值 | 含义 |
    |----|----|----|------|
    | 10 | LMA | 1 | Long Mode **已激活**（硬件置位，确认生效）|
    | 8  | LME | 1 | Long Mode **使能**（软件请求）|
    | 0  | SCE | 1 | 开启 `syscall`/`sysret` 指令 |

    LME + LMA 同时为 1，表示 CPU 确实已进入 64-bit Long Mode。

    ---*/
    sregs.efer = 0x0501;

    vcpu.set_sregs(&sregs).unwrap();
}

// ─── boot_params ─────────────────────────────────────────────────────────────

fn setup_boot_params(
    mem: &GuestMemoryMmap, mem_size: u64,
    cmdline_size: u32, initrd_addr: Option<GuestAddress>, initrd_size: u32,
) {
    let zp = ZERO_PAGE;
    macro_rules! w8  { ($o:expr,$v:expr) => { mem.write_obj($v as u8,  zp.unchecked_add($o)).unwrap() } }
    macro_rules! w16 { ($o:expr,$v:expr) => { mem.write_obj($v as u16, zp.unchecked_add($o)).unwrap() } }
    macro_rules! w32 { ($o:expr,$v:expr) => { mem.write_obj($v as u32, zp.unchecked_add($o)).unwrap() } }
    macro_rules! w64 { ($o:expr,$v:expr) => { mem.write_obj($v as u64, zp.unchecked_add($o)).unwrap() } }

    w16!(0x1fe, 0xAA55u16);
    w32!(0x202, 0x5372_6448u32);
    w16!(0x206, 0x020fu16);
    w8! (0x210, 0x81u8);
    w16!(0x224, 0xfe00u16);
    w8! (0x270, 0xffu8);
    w32!(0x228, CMDLINE_ADDR.raw_value() as u32);
    w32!(0x238, cmdline_size);
    w32!(0x22c, 0x7fff_ffffu32);

    if let Some(addr) = initrd_addr {
        w32!(0x218, addr.raw_value() as u32);
        w32!(0x21c, initrd_size);
    }

    let e820 = 0x2d0u64;
    let mut nr = 0u64;
    w64!(e820+nr*20,    0u64);        w64!(e820+nr*20+8, EBDA_START);      w32!(e820+nr*20+16, 1u32); nr+=1;
    w64!(e820+nr*20,    EBDA_START);  w64!(e820+nr*20+8, 0x10_0000-EBDA_START); w32!(e820+nr*20+16, 2u32); nr+=1;
    w64!(e820+nr*20,    0x10_0000u64); w64!(e820+nr*20+8, mem_size-0x10_0000); w32!(e820+nr*20+16, 1u32); nr+=1;
    w8!(0x1e8, nr as u8);
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let config = Config::parse();
    eprintln!("[mini-vmm] 内核  : {:?}", config.kernel);
    eprintln!("[mini-vmm] 命令行: {}", config.cmdline);
    eprintln!("[mini-vmm] 内存  : {} MiB\n", config.mem_size >> 20);

    let kvm = Kvm::new().expect("无法打开 /dev/kvm");
    let vm  = kvm.create_vm().expect("create_vm 失败");

    let guest_mem = GuestMemoryMmap::<()>::from_ranges(&[
        (GuestAddress(0), config.mem_size),
    ]).expect("分配 guest 内存失败");

    let host_addr = guest_mem.get_host_address(GuestAddress(0)).unwrap() as u64;
    unsafe {
        vm.set_user_memory_region(kvm_userspace_memory_region {
            slot: 0, guest_phys_addr: 0,
            memory_size: config.mem_size as u64,
            userspace_addr: host_addr, flags: 0,
        }).expect("注册内存失败");
    }

    setup_page_tables(&guest_mem);

    let mut kfile = File::open(&config.kernel)
        .unwrap_or_else(|e| panic!("无法打开内核: {e}"));
    let result = Elf::load(&guest_mem, None, &mut kfile, Some(GuestAddress(0x10_0000)))
        .unwrap_or_else(|e| panic!("加载 ELF 失败: {e}"));
    let entry = result.kernel_load.raw_value();
    eprintln!("[mini-vmm] 内核入口: {entry:#x}");

    let cmd = config.cmdline.as_bytes();
    assert!(cmd.len() < 4096);
    guest_mem.write_slice(cmd, CMDLINE_ADDR).unwrap();
    guest_mem.write_obj(0u8, CMDLINE_ADDR.unchecked_add(cmd.len() as u64)).unwrap();

    let (initrd_addr, initrd_size) = match &config.initrd {
        Some(path) => {
            let mut f = File::open(path).expect("无法打开 initrd");
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            let sz = buf.len() as u32;
            guest_mem.write_slice(&buf, INITRD_ADDR).unwrap();
            eprintln!("[mini-vmm] initrd: {} bytes", sz);
            (Some(INITRD_ADDR), sz)
        }
        None => (None, 0),
    };

    setup_boot_params(&guest_mem, config.mem_size as u64,
        cmd.len() as u32, initrd_addr, initrd_size);

    let mut vcpu = vm.create_vcpu(0).expect("create_vcpu 失败");

    // 关键：正确设置 CPUID，让内核使用 kvmclock
    setup_cpuid(&kvm, &vcpu);
    setup_sregs(&vcpu);

    let mut regs: kvm_regs = Default::default();
    regs.rflags = 0x0002;
    regs.rip    = entry;
    regs.rsi    = ZERO_PAGE.raw_value();
    regs.rsp    = 0x0000_8000;
    vcpu.set_regs(&regs).unwrap();

    let mut io = IoDevices::new();
    eprintln!("[mini-vmm] vCPU 启动，内核输出：\n{}", "─".repeat(60));

    loop {
        match vcpu.run().expect("vcpu.run() 失败") {
            VcpuExit::IoOut(port, data) => { io.write(port, data); }
            VcpuExit::IoIn(port, data)  => { io.read(port, data); }
            VcpuExit::MmioWrite(_, _)   => {}
            VcpuExit::MmioRead(_, data) => { for b in data.iter_mut() { *b = 0; } }
            VcpuExit::Hlt      => { eprintln!("\n[mini-vmm] HLT"); break; }
            VcpuExit::Shutdown => { eprintln!("\n[mini-vmm] Shutdown"); break; }
            other => { eprintln!("[mini-vmm] VM-Exit: {other:?}"); }
        }
    }
}