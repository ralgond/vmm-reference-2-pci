/// mini-vmm: 极简 x86_64 Linux VMM
///
/// 修复：补全早期启动所需的 IO 端口模拟
///  - PCI 配置空间 (0xCF8/0xCFC)
///  - PIT 8253 定时器 (0x40-0x43)
///  - 8042 PS/2 / NMI 控制器 (0x60/0x61/0x64)
///  - RTC/CMOS (0x70/0x71)
///  - POST code (0x80)
///  - 其余未知端口返回 0xFF 而非 0x00

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use kvm_bindings::{kvm_regs, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VcpuExit};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};
use linux_loader::loader::elf::Elf;
use linux_loader::loader::KernelLoader;

// ─── 物理内存布局 ─────────────────────────────────────────────────────────────
const GUEST_MEM_SIZE: usize = 256 * 1024 * 1024; // 256 MiB

const ZERO_PAGE:    GuestAddress = GuestAddress(0x0000_7000);
const PML4_ADDR:    u64 = 0x0001_0000;
const PDPT_ADDR:    u64 = 0x0001_1000;
const PD_BASE:      u64 = 0x0001_2000;
const CMDLINE_ADDR: GuestAddress = GuestAddress(0x0002_0000);
const INITRD_ADDR:  GuestAddress = GuestAddress(0x0800_0000);
const EBDA_START:   u64 = 0x0009_fc00;

const SERIAL_BASE: u16 = 0x3F8; // COM1

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
        let mut kernel   = None;
        let mut initrd   = None;
        let mut cmdline  = String::from(
            "console=ttyS0,115200 earlyprintk=ttyS0,115200 \
             noapic nolapic pci=off nomodules panic=-1 \
             clocksource=tsc tsc=reliable",
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
                    mem_size = args[i].parse::<usize>().expect("--mem 需要整数(MB)") << 20;
                }
                "--help" | "-h" => {
                    eprintln!("用法: mini-vmm --kernel <vmlinux> [--initrd <img>] [--cmdline \"...\"] [--mem <MB>]");
                    std::process::exit(0);
                }
                _ => {}
            }
            i += 1;
        }
        Config {
            kernel:  kernel.expect("必须通过 --kernel 指定 ELF vmlinux 路径"),
            initrd,
            cmdline,
            mem_size,
        }
    }
}

// ─── IO 设备模拟 ──────────────────────────────────────────────────────────────

struct IoDevices {
    // COM1 串口
    serial_lcr: u8,   // Line Control Register (DLAB bit)
    serial_ier: u8,   // Interrupt Enable Register

    // PIT 8253
    pit_ch2: u8,

    // CMOS
    cmos_index: u8,

    // PCI 配置空间地址寄存器
    pci_addr: u32,
}

impl IoDevices {
    fn new() -> Self {
        IoDevices {
            serial_lcr: 0,
            serial_ier: 0,
            pit_ch2: 0,
            cmos_index: 0,
            pci_addr: 0,
        }
    }

    fn io_write(&mut self, port: u16, data: &[u8]) {
        let val = data[0];
        match port {
            // ── COM1 串口 (0x3F8 - 0x3FF) ─────────────────────────────────
            0x3F8 => {
                // THR 或 DLL（DLAB=1 时为波特率低字节，忽略）
                if self.serial_lcr & 0x80 == 0 {
                    // DLAB=0: 发送字符
                    print!("{}", val as char);
                    let _ = io::stdout().flush();
                }
                // DLAB=1: 波特率设置，忽略
            }
            0x3F9 => { self.serial_ier = val; }   // IER / DLM
            0x3FA => {}  // FCR (FIFO 控制，忽略)
            0x3FB => { self.serial_lcr = val; }   // LCR
            0x3FC => {}  // MCR
            0x3FD => {}  // LSR (只读)
            0x3FE => {}  // MSR (只读)
            0x3FF => {}  // SCR (暂存器)

            // ── PIT 8253 定时器 (0x40-0x43) ───────────────────────────────
            0x40 => {}  // Channel 0 (系统时钟)，写忽略
            0x41 => {}  // Channel 1 (RAM 刷新)，忽略
            0x42 => { self.pit_ch2 = val; }  // Channel 2 (扬声器)
            0x43 => {}  // 控制字，忽略

            // ── 8042 / NMI 端口 ────────────────────────────────────────────
            0x61 => {}  // NMI 状态/控制
            0x64 => {}  // 8042 命令端口，忽略

            // ── RTC/CMOS ──────────────────────────────────────────────────
            0x70 => { self.cmos_index = val & 0x7f; }  // CMOS 索引（屏蔽 NMI 位）
            0x71 => {}  // CMOS 数据写，忽略

            // ── PCI 配置空间 ───────────────────────────────────────────────
            0xCF8 => {
                // 地址寄存器（4字节）
                self.pci_addr = u32::from_le_bytes([
                    data[0],
                    data.get(1).copied().unwrap_or(0),
                    data.get(2).copied().unwrap_or(0),
                    data.get(3).copied().unwrap_or(0),
                ]);
            }
            0xCF9 => {}  // PCI 复位控制
            0xCFA..=0xCFF => {}  // PCI 数据端口写，忽略

            // ── 其他常见端口 ───────────────────────────────────────────────
            0x80 => {}  // POST debug code，忽略
            0x92 => {}  // Port A (A20 等)，忽略
            0x20 | 0x21 => {}  // PIC 主片
            0xA0 | 0xA1 => {}  // PIC 从片
            0x60 => {}  // PS/2 数据端口

            _ => {
                // 其余端口写：静默忽略
            }
        }
    }

    fn io_read(&mut self, port: u16, data: &mut [u8]) {
        let val: u8 = match port {
            // ── COM1 串口 ──────────────────────────────────────────────────
            0x3F8 => 0x00,  // RBR: 无数据
            0x3F9 => self.serial_ier,
            0x3FA => 0x01,  // IIR: 无中断 (bit0=1)
            0x3FB => self.serial_lcr,
            0x3FC => 0x00,  // MCR
            // LSR: bit5=THRE(发送缓冲空) + bit6=TEMT(发送完成)
            // 不设 bit0(DR)，避免内核认为有输入数据
            0x3FD => 0x60,
            0x3FE => 0xB0,  // MSR: CTS + DSR + DCD
            0x3FF => 0x00,  // SCR

            // ── PIT ────────────────────────────────────────────────────────
            // 返回一个递减计数值，让内核认为定时器在走
            0x40 => 0x00,
            0x41 => 0x00,
            0x42 => self.pit_ch2,

            // ── 8042 / NMI ─────────────────────────────────────────────────
            // 0x61 bit5=0(扬声器数据)，bit4=0(RAM 奇偶校验),
            //       bit5=1 表示 PIT ch2 输出（某些内核会等这位）
            0x61 => 0x20,  // bit5=1: PIT ch2 输出高
            // 0x64: 状态寄存器 bit0=0(输出缓冲空) bit1=0(输入缓冲空)
            0x64 => 0x00,
            0x60 => 0x00,  // PS/2 数据

            // ── RTC/CMOS ──────────────────────────────────────────────────
            0x71 => {
                match self.cmos_index {
                    0x0a => 0x00,  // 状态寄存器A: UIP=0(更新未进行)
                    0x0b => 0x02,  // 状态寄存器B: 24h制
                    0x0d => 0x80,  // 状态寄存器D: VRT=1(电池正常)
                    _    => 0x00,
                }
            }
            0x70 => self.cmos_index,

            // ── PCI 配置空间 ───────────────────────────────────────────────
            // 返回 0xFFFFFFFF 表示设备不存在（标准 PCIe 约定）
            0xCF8 => (self.pci_addr & 0xff) as u8,
            0xCFC..=0xCFF => 0xFF,  // 不存在的 PCI 设备

            // ── PIC ────────────────────────────────────────────────────────
            0x20 => 0x00,
            0x21 => 0xFF,  // IMR: 屏蔽所有中断
            0xA0 => 0x00,
            0xA1 => 0xFF,

            // ── 其余端口 ───────────────────────────────────────────────────
            // 返回 0xFF 比 0x00 更安全（表示"无设备"）
            _ => 0xFF,
        };

        for b in data.iter_mut() {
            *b = val;
        }

        // 对于多字节读（如 PCI 0xCF8），特殊处理
        if port == 0xCF8 && data.len() == 4 {
            let bytes = self.pci_addr.to_le_bytes();
            data.copy_from_slice(&bytes);
        }
        if (port == 0xCFC || port == 0xCFD || port == 0xCFE || port == 0xCFF) && data.len() >= 1 {
            // PCI 数据端口：返回全 0xFF（设备不存在）
            for b in data.iter_mut() { *b = 0xFF; }
        }
    }
}

// ─── 页表：identity map 前 4GiB，2MiB 大页 ───────────────────────────────────

fn setup_page_tables(mem: &GuestMemoryMmap) {
    mem.write_obj(PDPT_ADDR | 0x03u64, GuestAddress(PML4_ADDR)).unwrap();

    for i in 0..4u64 {
        mem.write_obj(
            (PD_BASE + i * 0x1000) | 0x03u64,
            GuestAddress(PDPT_ADDR + i * 8),
        ).unwrap();

        for j in 0..512u64 {
            let phys = (i << 30) | (j << 21);
            mem.write_obj(
                phys | 0x83u64, // P + RW + PS(2MiB)
                GuestAddress(PD_BASE + i * 0x1000 + j * 8),
            ).unwrap();
        }
    }
}

// ─── 分段 & 控制寄存器 ────────────────────────────────────────────────────────

fn setup_sregs(vcpu: &kvm_ioctls::VcpuFd) {
    let mut sregs = vcpu.get_sregs().unwrap();

    let cs = kvm_bindings::kvm_segment {
        base: 0, limit: 0xffff_ffff, selector: 0x08,
        type_: 0x0b, present: 1, dpl: 0, db: 0, s: 1, l: 1, g: 1, avl: 0,
        ..Default::default()
    };
    let ds = kvm_bindings::kvm_segment {
        base: 0, limit: 0xffff_ffff, selector: 0x10,
        type_: 0x03, present: 1, dpl: 0, db: 1, s: 1, l: 0, g: 1, avl: 0,
        ..Default::default()
    };

    sregs.cs = cs;
    sregs.ds = ds; sregs.es = ds; sregs.fs = ds; sregs.gs = ds; sregs.ss = ds;

    sregs.cr3  = PML4_ADDR;
    sregs.cr0  = 0x8005_0033;  // PE + MP + ET + NE + WP + PG
    sregs.cr4  = 0x0000_02a0;  // PAE + PGE + OSFXSR
    sregs.efer = 0x0501;       // SCE + LME + LMA

    vcpu.set_sregs(&sregs).unwrap();
}

// ─── boot_params ─────────────────────────────────────────────────────────────

fn setup_boot_params(
    mem:          &GuestMemoryMmap,
    mem_size:     u64,
    cmdline_size: u32,
    initrd_addr:  Option<GuestAddress>,
    initrd_size:  u32,
) {
    let zp = ZERO_PAGE;
    macro_rules! w8  { ($off:expr, $v:expr) => { mem.write_obj($v as u8,  zp.unchecked_add($off)).unwrap() } }
    macro_rules! w16 { ($off:expr, $v:expr) => { mem.write_obj($v as u16, zp.unchecked_add($off)).unwrap() } }
    macro_rules! w32 { ($off:expr, $v:expr) => { mem.write_obj($v as u32, zp.unchecked_add($off)).unwrap() } }
    macro_rules! w64 { ($off:expr, $v:expr) => { mem.write_obj($v as u64, zp.unchecked_add($off)).unwrap() } }

    // setup_header 字段（偏移相对 zero_page 基址）
    w16!(0x1fe, 0xAA55u16);                              // boot_flag
    w32!(0x202, 0x5372_6448u32);                         // "HdrS" magic
    w16!(0x206, 0x020fu16);                              // version 2.15
    w8! (0x210, 0x81u8);                                 // loadflags: LOADED_HIGH | CAN_USE_HEAP
    w16!(0x224, 0xfe00u16);                              // heap_end_ptr
    w8! (0x270, 0xffu8);                                 // type_of_loader
    w32!(0x228, CMDLINE_ADDR.raw_value() as u32);        // cmdline_ptr
    w32!(0x238, cmdline_size);                           // cmdline_size
    w32!(0x22c, 0x7fff_ffffu32);                         // initrd_addr_max

    if let Some(addr) = initrd_addr {
        w32!(0x218, addr.raw_value() as u32);  // ramdisk_image
        w32!(0x21c, initrd_size);              // ramdisk_size
    }

    // E820 表
    let e820 = 0x2d0u64;
    let mut nr = 0u64;

    w64!(e820 + nr*20,      0u64);          // [0, EBDA) = RAM
    w64!(e820 + nr*20 + 8,  EBDA_START);
    w32!(e820 + nr*20 + 16, 1u32);
    nr += 1;

    w64!(e820 + nr*20,      EBDA_START);    // [EBDA, 1MiB) = Reserved
    w64!(e820 + nr*20 + 8,  0x10_0000 - EBDA_START);
    w32!(e820 + nr*20 + 16, 2u32);
    nr += 1;

    w64!(e820 + nr*20,      0x10_0000u64);  // [1MiB, mem_size) = RAM
    w64!(e820 + nr*20 + 8,  mem_size - 0x10_0000);
    w32!(e820 + nr*20 + 16, 1u32);
    nr += 1;

    w8!(0x1e8, nr as u8);  // e820_entries
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let config = Config::parse();
    eprintln!("[mini-vmm] 内核  : {:?}", config.kernel);
    eprintln!("[mini-vmm] 命令行: {}", config.cmdline);
    eprintln!("[mini-vmm] 内存  : {} MiB\n", config.mem_size >> 20);

    let kvm = Kvm::new().expect("无法打开 /dev/kvm");
    let vm  = kvm.create_vm().expect("create_vm 失败");

    // Guest 内存
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

    // 页表
    setup_page_tables(&guest_mem);

    // 加载 ELF vmlinux
    let mut kfile = File::open(&config.kernel)
        .unwrap_or_else(|e| panic!("无法打开内核文件: {e}"));
    let result = Elf::load(
        &guest_mem, None, &mut kfile,
        Some(GuestAddress(0x10_0000)),
    ).unwrap_or_else(|e| panic!("加载 ELF 失败: {e}"));
    let entry = result.kernel_load.raw_value();
    eprintln!("[mini-vmm] 内核入口: {entry:#x}");

    // Cmdline
    let cmd = config.cmdline.as_bytes();
    assert!(cmd.len() < 4096);
    guest_mem.write_slice(cmd, CMDLINE_ADDR).unwrap();
    guest_mem.write_obj(0u8, CMDLINE_ADDR.unchecked_add(cmd.len() as u64)).unwrap();

    // Initrd
    let (initrd_addr, initrd_size) = match &config.initrd {
        Some(path) => {
            let mut f = File::open(path).expect("无法打开 initrd");
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            let sz = buf.len() as u32;
            guest_mem.write_slice(&buf, INITRD_ADDR).unwrap();
            eprintln!("[mini-vmm] initrd: {} bytes @ {:#x}", sz, INITRD_ADDR.raw_value());
            (Some(INITRD_ADDR), sz)
        }
        None => (None, 0),
    };

    // boot_params
    setup_boot_params(
        &guest_mem, config.mem_size as u64,
        cmd.len() as u32, initrd_addr, initrd_size,
    );

    // vCPU
    let mut vcpu = vm.create_vcpu(0).expect("create_vcpu 失败");
    let cpuid = kvm.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
    vcpu.set_cpuid2(&cpuid).unwrap();
    setup_sregs(&vcpu);

    let mut regs: kvm_regs = Default::default();
    regs.rflags = 0x0002;
    regs.rip    = entry;
    regs.rsi    = ZERO_PAGE.raw_value();
    regs.rsp    = 0x0000_8000;
    vcpu.set_regs(&regs).unwrap();

    // 运行循环
    let mut io = IoDevices::new();
    eprintln!("[mini-vmm] vCPU 启动，内核输出：\n{}", "─".repeat(60));

    loop {
        match vcpu.run().expect("vcpu.run() 失败") {

            VcpuExit::IoOut(port, data) => {
                io.io_write(port, data);
            }

            VcpuExit::IoIn(port, data) => {
                io.io_read(port, data);
            }

            VcpuExit::MmioWrite(_, _) => {}

            VcpuExit::MmioRead(_, data) => {
                for b in data.iter_mut() { *b = 0; }
            }

            VcpuExit::Hlt => {
                eprintln!("\n[mini-vmm] Guest HLT，退出");
                break;
            }

            VcpuExit::Shutdown => {
                eprintln!("\n[mini-vmm] Guest 关机 (triple fault)");
                break;
            }

            other => {
                eprintln!("[mini-vmm] VM-Exit: {other:?}");
            }
        }
    }
}