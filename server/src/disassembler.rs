/// Dalvik bytecode disassembler.
/// Decodes raw DEX bytecodes into human-readable smali-like text.
/// Supports ~60 most common opcodes; unknown opcodes show as `unknown_XX`.

use crate::dex_parser::DexData;

/// Condition for a conditional branch instruction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BranchCond {
    Always,                    // goto
    Eq, Ne, Lt, Ge, Gt, Le,   // if-XX vA, vB
    Eqz, Nez, Ltz, Gez, Gtz, Lez, // if-XXz vA
}

/// Branch metadata for control-flow instructions.
#[derive(Debug, Clone)]
pub struct BranchMeta {
    pub target: u32,           // target offset in code units
    pub cond: BranchCond,
    pub reg_a: u8,             // first register
    pub reg_b: Option<u8>,     // second register (None for if-XXz and goto)
}

/// A single disassembled instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Offset in Dalvik code units from start of method bytecodes.
    /// (Each code unit = 2 bytes. This matches jlocation values from JVMTI.)
    pub offset: u32,
    /// Width in code units (each code unit = 2 bytes).
    pub width: u32,
    /// Human-readable disassembly text.
    pub text: String,
    /// Branch metadata (for goto/if-* instructions).
    pub branch: Option<BranchMeta>,
    /// DEX method index for invoke-* instructions (for double-click follow).
    pub method_idx: Option<u16>,
}

/// Disassemble raw Dalvik bytecodes into a list of instructions.
/// If `dex` is provided, constant pool references are resolved to names.
pub fn disassemble(bytecodes: &[u8], dex: Option<&DexData>) -> Vec<Instruction> {
    let mut result = Vec::new();
    let mut pc: usize = 0;
    let len = bytecodes.len();

    while pc < len {
        let start_pc = pc;
        let op = bytecodes[pc];

        let (width_units, text) = decode_instruction(bytecodes, pc, len, dex);
        let branch = decode_branch(bytecodes, pc, op);
        let width_bytes = (width_units as usize) * 2;

        // Extract method_idx for invoke-* instructions (for double-click follow)
        let method_idx = match op {
            0x6e..=0x72 | 0x74..=0x78 => Some(u16_at(bytecodes, pc + 2)),
            _ => None,
        };

        result.push(Instruction {
            offset: (start_pc / 2) as u32,
            width: width_units,
            text,
            branch,
            method_idx,
        });

        pc += width_bytes;
        if width_bytes == 0 {
            pc += 2;
        }
    }

    result
}

/// Extract branch metadata from an instruction (if it's a branch).
fn decode_branch(bc: &[u8], pc: usize, op: u8) -> Option<BranchMeta> {
    match op {
        // goto (10t)
        0x28 => {
            let off = bc.get(pc + 1).copied().unwrap_or(0) as i8;
            let target = (pc / 2) as i32 + (off as i32);
            Some(BranchMeta { target: target.max(0) as u32, cond: BranchCond::Always, reg_a: 0, reg_b: None })
        }
        // goto/16 (20t)
        0x29 => {
            let off = i16_at(bc, pc + 2);
            let target = (pc / 2) as i32 + (off as i32);
            Some(BranchMeta { target: target.max(0) as u32, cond: BranchCond::Always, reg_a: 0, reg_b: None })
        }
        // goto/32 (30t)
        0x2a => {
            let off = i32_at(bc, pc + 2);
            let target = (pc / 2) as i32 + off;
            Some(BranchMeta { target: target.max(0) as u32, cond: BranchCond::Always, reg_a: 0, reg_b: None })
        }
        // if-test (22t): if-eq, if-ne, if-lt, if-ge, if-gt, if-le
        0x32..=0x37 => {
            let conds = [BranchCond::Eq, BranchCond::Ne, BranchCond::Lt, BranchCond::Ge, BranchCond::Gt, BranchCond::Le];
            let off = i16_at(bc, pc + 2);
            let target = (pc / 2) as i32 + (off as i32);
            Some(BranchMeta {
                target: target.max(0) as u32,
                cond: conds[(op - 0x32) as usize],
                reg_a: reg_a(bc, pc),
                reg_b: Some(reg_b(bc, pc)),
            })
        }
        // if-testz (21t): if-eqz, if-nez, if-ltz, if-gez, if-gtz, if-lez
        0x38..=0x3d => {
            let conds = [BranchCond::Eqz, BranchCond::Nez, BranchCond::Ltz, BranchCond::Gez, BranchCond::Gtz, BranchCond::Lez];
            let off = i16_at(bc, pc + 2);
            let target = (pc / 2) as i32 + (off as i32);
            Some(BranchMeta {
                target: target.max(0) as u32,
                cond: conds[(op - 0x38) as usize],
                reg_a: reg_aa(bc, pc),
                reg_b: None,
            })
        }
        _ => None,
    }
}

/// Evaluate a conditional branch. Returns Some(true) if taken, Some(false) if not,
/// None if register values are unavailable.
pub fn eval_branch(meta: &BranchMeta, get_reg: &dyn Fn(u8) -> Option<i64>) -> Option<bool> {
    match meta.cond {
        BranchCond::Always => Some(true),
        // if-XX vA, vB
        BranchCond::Eq | BranchCond::Ne | BranchCond::Lt |
        BranchCond::Ge | BranchCond::Gt | BranchCond::Le => {
            let a = get_reg(meta.reg_a)?;
            let b = get_reg(meta.reg_b?)?;
            Some(match meta.cond {
                BranchCond::Eq => a == b,
                BranchCond::Ne => a != b,
                BranchCond::Lt => a < b,
                BranchCond::Ge => a >= b,
                BranchCond::Gt => a > b,
                BranchCond::Le => a <= b,
                _ => unreachable!(),
            })
        }
        // if-XXz vA
        BranchCond::Eqz | BranchCond::Nez | BranchCond::Ltz |
        BranchCond::Gez | BranchCond::Gtz | BranchCond::Lez => {
            let a = get_reg(meta.reg_a)?;
            Some(match meta.cond {
                BranchCond::Eqz => a == 0,
                BranchCond::Nez => a != 0,
                BranchCond::Ltz => a < 0,
                BranchCond::Gez => a >= 0,
                BranchCond::Gtz => a > 0,
                BranchCond::Lez => a <= 0,
                _ => unreachable!(),
            })
        }
    }
}

// Read a u16 at byte offset (little-endian), or 0 if out of bounds.
fn u16_at(bc: &[u8], off: usize) -> u16 {
    if off + 1 < bc.len() {
        u16::from_le_bytes([bc[off], bc[off + 1]])
    } else {
        0
    }
}

fn i16_at(bc: &[u8], off: usize) -> i16 {
    u16_at(bc, off) as i16
}

fn u32_at(bc: &[u8], off: usize) -> u32 {
    if off + 3 < bc.len() {
        u32::from_le_bytes([bc[off], bc[off + 1], bc[off + 2], bc[off + 3]])
    } else {
        0
    }
}

fn i32_at(bc: &[u8], off: usize) -> i32 {
    u32_at(bc, off) as i32
}

// Nibble extraction from format bytes
fn reg_a(bc: &[u8], pc: usize) -> u8 {
    if pc + 1 < bc.len() { bc[pc + 1] & 0x0F } else { 0 }
}
fn reg_b(bc: &[u8], pc: usize) -> u8 {
    if pc + 1 < bc.len() { (bc[pc + 1] >> 4) & 0x0F } else { 0 }
}
fn reg_aa(bc: &[u8], pc: usize) -> u8 {
    if pc + 1 < bc.len() { bc[pc + 1] } else { 0 }
}

/// Resolve a string index: show "quoted" if available, else string@xxxx.
fn resolve_string(dex: Option<&DexData>, idx: u16) -> String {
    if let Some(d) = dex {
        if let Some(s) = d.get_string(idx as u32) {
            let cut = s.char_indices().nth(32).map(|(i, _)| i).unwrap_or(s.len());
            let display = &s[..cut];
            return format!("\"{}\"", display);
        }
    }
    format!("string@{:04x}", idx)
}

/// Resolve a type index: show short name if available, else type@xxxx.
fn resolve_type(dex: Option<&DexData>, idx: u16) -> String {
    if let Some(d) = dex {
        if let Some(s) = d.get_type_short(idx as u32) {
            return s;
        }
    }
    format!("type@{:04x}", idx)
}

/// Resolve a method index: show Class.method if available, else method@xxxx.
fn resolve_method(dex: Option<&DexData>, idx: u16) -> String {
    if let Some(d) = dex {
        if let Some(s) = d.get_method_display(idx as u32) {
            return s;
        }
    }
    format!("method@{:04x}", idx)
}

/// Resolve a field index: show Class.field:type if available, else field@xxxx.
fn resolve_field(dex: Option<&DexData>, idx: u16) -> String {
    if let Some(d) = dex {
        if let Some(s) = d.get_field_display(idx as u32) {
            return s;
        }
    }
    format!("field@{:04x}", idx)
}

/// Decode one instruction at `pc`. Returns (width_in_code_units, text).
fn decode_instruction(bc: &[u8], pc: usize, _len: usize, dex: Option<&DexData>) -> (u32, String) {
    let op = bc[pc];

    match op {
        // 10x  - nop
        0x00 => {
            // Check for packed-switch/sparse-switch/fill-array-data payloads
            let ident = u16_at(bc, pc);
            match ident {
                0x0100 => {
                    // packed-switch payload
                    let size = u16_at(bc, pc + 2) as u32;
                    let w = 2 + size * 2; // size entries + header
                    (w.max(1), format!("packed-switch-data ({} entries)", size))
                }
                0x0200 => {
                    // sparse-switch payload
                    let size = u16_at(bc, pc + 2) as u32;
                    let w = 2 + size * 4;
                    (w.max(1), format!("sparse-switch-data ({} entries)", size))
                }
                0x0300 => {
                    // fill-array-data payload
                    let elem_width = u16_at(bc, pc + 2) as u32;
                    let count = u32_at(bc, pc + 4);
                    let data_bytes = elem_width * count;
                    let w = 4 + (data_bytes + 1) / 2;
                    (w.max(1), format!("fill-array-data ({} x {} bytes)", count, elem_width))
                }
                _ => (1, "nop".into()),
            }
        }

        // 12x  - move vA, vB
        0x01 => (1, format!("move v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        // 22x  - move/from16 vAA, vBBBB
        0x02 => (2, format!("move/from16 v{}, v{}", reg_aa(bc, pc), u16_at(bc, pc + 2))),
        // 32x  - move/16 vAAAA, vBBBB
        0x03 => (3, format!("move/16 v{}, v{}", u16_at(bc, pc + 2), u16_at(bc, pc + 4))),
        // 12x  - move-wide
        0x04 => (1, format!("move-wide v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x05 => (2, format!("move-wide/from16 v{}, v{}", reg_aa(bc, pc), u16_at(bc, pc + 2))),
        0x06 => (3, format!("move-wide/16 v{}, v{}", u16_at(bc, pc + 2), u16_at(bc, pc + 4))),
        // move-object
        0x07 => (1, format!("move-object v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x08 => (2, format!("move-object/from16 v{}, v{}", reg_aa(bc, pc), u16_at(bc, pc + 2))),
        0x09 => (3, format!("move-object/16 v{}, v{}", u16_at(bc, pc + 2), u16_at(bc, pc + 4))),
        // move-result
        0x0a => (1, format!("move-result v{}", reg_aa(bc, pc))),
        0x0b => (1, format!("move-result-wide v{}", reg_aa(bc, pc))),
        0x0c => (1, format!("move-result-object v{}", reg_aa(bc, pc))),
        0x0d => (1, format!("move-exception v{}", reg_aa(bc, pc))),

        // 10x  - return-void
        0x0e => (1, "return-void".into()),
        0x0f => (1, format!("return v{}", reg_aa(bc, pc))),
        0x10 => (1, format!("return-wide v{}", reg_aa(bc, pc))),
        0x11 => (1, format!("return-object v{}", reg_aa(bc, pc))),

        // const/4 vA, #+B (11n)
        0x12 => {
            let a = reg_a(bc, pc);
            let b = (reg_b(bc, pc) as i8) << 4 >> 4; // sign-extend nibble
            (1, format!("const/4 v{}, #{}", a, b))
        }
        // const/16 vAA, #+BBBB (21s)
        0x13 => (2, format!("const/16 v{}, #{}", reg_aa(bc, pc), i16_at(bc, pc + 2))),
        // const vAA, #+BBBBBBBB (31i)
        0x14 => (3, format!("const v{}, #{}", reg_aa(bc, pc), i32_at(bc, pc + 2))),
        // const/high16 vAA, #+BBBB0000 (21h)
        0x15 => (2, format!("const/high16 v{}, #{}", reg_aa(bc, pc), (i16_at(bc, pc + 2) as i32) << 16)),
        // const-wide/16 (21s)
        0x16 => (2, format!("const-wide/16 v{}, #{}", reg_aa(bc, pc), i16_at(bc, pc + 2))),
        // const-wide/32 (31i)
        0x17 => (3, format!("const-wide/32 v{}, #{}", reg_aa(bc, pc), i32_at(bc, pc + 2))),
        // const-wide (51l)
        0x18 => {
            let lo = u32_at(bc, pc + 2) as u64;
            let hi = u32_at(bc, pc + 6) as u64;
            let val = (hi << 32) | lo;
            (5, format!("const-wide v{}, #0x{:x}", reg_aa(bc, pc), val))
        }
        // const-wide/high16 (21h)
        0x19 => (2, format!("const-wide/high16 v{}, #{}", reg_aa(bc, pc), (i16_at(bc, pc + 2) as i64) << 48)),
        // const-string (21c)
        0x1a => (2, format!("const-string v{}, {}", reg_aa(bc, pc), resolve_string(dex, u16_at(bc, pc + 2)))),
        // const-string/jumbo (31c)
        0x1b => {
            let idx = u32_at(bc, pc + 2);
            let resolved = if let Some(d) = dex {
                if let Some(s) = d.get_string(idx) {
                    let cut = s.char_indices().nth(32).map(|(i, _)| i).unwrap_or(s.len());
            let display = &s[..cut];
                    format!("\"{}\"", display)
                } else {
                    format!("string@{:08x}", idx)
                }
            } else {
                format!("string@{:08x}", idx)
            };
            (3, format!("const-string/jumbo v{}, {}", reg_aa(bc, pc), resolved))
        }
        // const-class (21c)
        0x1c => (2, format!("const-class v{}, {}", reg_aa(bc, pc), resolve_type(dex, u16_at(bc, pc + 2)))),

        // monitor-enter, monitor-exit (11x)
        0x1d => (1, format!("monitor-enter v{}", reg_aa(bc, pc))),
        0x1e => (1, format!("monitor-exit v{}", reg_aa(bc, pc))),

        // check-cast (21c)
        0x1f => (2, format!("check-cast v{}, {}", reg_aa(bc, pc), resolve_type(dex, u16_at(bc, pc + 2)))),
        // instance-of (22c)
        0x20 => (2, format!("instance-of v{}, v{}, {}", reg_a(bc, pc), reg_b(bc, pc), resolve_type(dex, u16_at(bc, pc + 2)))),
        // array-length (12x)
        0x21 => (1, format!("array-length v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        // new-instance (21c)
        0x22 => (2, format!("new-instance v{}, {}", reg_aa(bc, pc), resolve_type(dex, u16_at(bc, pc + 2)))),
        // new-array (22c)
        0x23 => (2, format!("new-array v{}, v{}, {}", reg_a(bc, pc), reg_b(bc, pc), resolve_type(dex, u16_at(bc, pc + 2)))),

        // filled-new-array (35c)
        0x24 => {
            let idx = u16_at(bc, pc + 2);
            (3, format!("filled-new-array {}", resolve_type(dex, idx)))
        }
        // filled-new-array/range (3rc)
        0x25 => {
            let idx = u16_at(bc, pc + 2);
            (3, format!("filled-new-array/range {}", resolve_type(dex, idx)))
        }
        // fill-array-data (31t)
        0x26 => {
            let offset = i32_at(bc, pc + 2);
            (3, format!("fill-array-data v{}, +{}", reg_aa(bc, pc), offset))
        }

        // throw (11x)
        0x27 => (1, format!("throw v{}", reg_aa(bc, pc))),

        // goto (10t)
        0x28 => {
            let off = bc[pc + 1] as i8;
            let target = (pc / 2) as i32 + (off as i32);
            (1, format!("goto {:04x}", target))
        }
        // goto/16 (20t)
        0x29 => {
            let off = i16_at(bc, pc + 2);
            let target = (pc / 2) as i32 + (off as i32);
            (2, format!("goto/16 {:04x}", target))
        }
        // goto/32 (30t)
        0x2a => {
            let off = i32_at(bc, pc + 2);
            let target = (pc / 2) as i32 + off;
            (3, format!("goto/32 {:04x}", target))
        }

        // packed-switch (31t)
        0x2b => {
            let off = i32_at(bc, pc + 2);
            (3, format!("packed-switch v{}, +{}", reg_aa(bc, pc), off))
        }
        // sparse-switch (31t)
        0x2c => {
            let off = i32_at(bc, pc + 2);
            (3, format!("sparse-switch v{}, +{}", reg_aa(bc, pc), off))
        }

        // cmpX (23x)  - compare
        0x2d => (2, format!("cmpl-float v{}, v{}, v{}", reg_aa(bc, pc), bc.get(pc + 2).copied().unwrap_or(0), bc.get(pc + 3).copied().unwrap_or(0))),
        0x2e => (2, format!("cmpg-float v{}, v{}, v{}", reg_aa(bc, pc), bc.get(pc + 2).copied().unwrap_or(0), bc.get(pc + 3).copied().unwrap_or(0))),
        0x2f => (2, format!("cmpl-double v{}, v{}, v{}", reg_aa(bc, pc), bc.get(pc + 2).copied().unwrap_or(0), bc.get(pc + 3).copied().unwrap_or(0))),
        0x30 => (2, format!("cmpg-double v{}, v{}, v{}", reg_aa(bc, pc), bc.get(pc + 2).copied().unwrap_or(0), bc.get(pc + 3).copied().unwrap_or(0))),
        0x31 => (2, format!("cmp-long v{}, v{}, v{}", reg_aa(bc, pc), bc.get(pc + 2).copied().unwrap_or(0), bc.get(pc + 3).copied().unwrap_or(0))),

        // if-test (22t)  - conditional branches
        0x32..=0x37 => {
            let names = ["if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"];
            let name = names[(op - 0x32) as usize];
            let off = i16_at(bc, pc + 2);
            let target = (pc / 2) as i32 + (off as i32);
            (2, format!("{} v{}, v{}, {:04x}", name, reg_a(bc, pc), reg_b(bc, pc), target))
        }
        // if-testz (21t)  - conditional branches against zero
        0x38..=0x3d => {
            let names = ["if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"];
            let name = names[(op - 0x38) as usize];
            let off = i16_at(bc, pc + 2);
            let target = (pc / 2) as i32 + (off as i32);
            (2, format!("{} v{}, {:04x}", name, reg_aa(bc, pc), target))
        }

        // aget (23x)
        0x44..=0x4a => {
            let names = ["aget", "aget-wide", "aget-object", "aget-boolean",
                         "aget-byte", "aget-char", "aget-short"];
            let name = names[(op - 0x44) as usize];
            let aa = reg_aa(bc, pc);
            let cc = bc.get(pc + 2).copied().unwrap_or(0);
            let dd = bc.get(pc + 3).copied().unwrap_or(0);
            (2, format!("{} v{}, v{}, v{}", name, aa, cc, dd))
        }
        // aput (23x)
        0x4b..=0x51 => {
            let names = ["aput", "aput-wide", "aput-object", "aput-boolean",
                         "aput-byte", "aput-char", "aput-short"];
            let name = names[(op - 0x4b) as usize];
            let aa = reg_aa(bc, pc);
            let cc = bc.get(pc + 2).copied().unwrap_or(0);
            let dd = bc.get(pc + 3).copied().unwrap_or(0);
            (2, format!("{} v{}, v{}, v{}", name, aa, cc, dd))
        }

        // iget (22c)
        0x52..=0x58 => {
            let names = ["iget", "iget-wide", "iget-object", "iget-boolean",
                         "iget-byte", "iget-char", "iget-short"];
            let name = names[(op - 0x52) as usize];
            let idx = u16_at(bc, pc + 2);
            (2, format!("{} v{}, v{}, {}", name, reg_a(bc, pc), reg_b(bc, pc), resolve_field(dex, idx)))
        }
        // iput (22c)
        0x59..=0x5f => {
            let names = ["iput", "iput-wide", "iput-object", "iput-boolean",
                         "iput-byte", "iput-char", "iput-short"];
            let name = names[(op - 0x59) as usize];
            let idx = u16_at(bc, pc + 2);
            (2, format!("{} v{}, v{}, {}", name, reg_a(bc, pc), reg_b(bc, pc), resolve_field(dex, idx)))
        }

        // sget (21c)
        0x60..=0x66 => {
            let names = ["sget", "sget-wide", "sget-object", "sget-boolean",
                         "sget-byte", "sget-char", "sget-short"];
            let name = names[(op - 0x60) as usize];
            let idx = u16_at(bc, pc + 2);
            (2, format!("{} v{}, {}", name, reg_aa(bc, pc), resolve_field(dex, idx)))
        }
        // sput (21c)
        0x67..=0x6d => {
            let names = ["sput", "sput-wide", "sput-object", "sput-boolean",
                         "sput-byte", "sput-char", "sput-short"];
            let name = names[(op - 0x67) as usize];
            let idx = u16_at(bc, pc + 2);
            (2, format!("{} v{}, {}", name, reg_aa(bc, pc), resolve_field(dex, idx)))
        }

        // invoke-kind (35c)
        0x6e..=0x72 => {
            let names = ["invoke-virtual", "invoke-super", "invoke-direct",
                         "invoke-static", "invoke-interface"];
            let name = names[(op - 0x6e) as usize];
            let count = reg_b(bc, pc);
            let method_idx = u16_at(bc, pc + 2);
            let regs = decode_invoke_regs(bc, pc, count);
            (3, format!("{} {{{}}}, {}", name, regs, resolve_method(dex, method_idx)))
        }

        // invoke-kind/range (3rc)
        0x74..=0x78 => {
            let names = ["invoke-virtual/range", "invoke-super/range", "invoke-direct/range",
                         "invoke-static/range", "invoke-interface/range"];
            let name = names[(op - 0x74) as usize];
            let count = reg_aa(bc, pc);
            let method_idx = u16_at(bc, pc + 2);
            let first_reg = u16_at(bc, pc + 4);
            let resolved = resolve_method(dex, method_idx);
            if count == 0 {
                (3, format!("{} {{}}, {}", name, resolved))
            } else if count == 1 {
                (3, format!("{} {{v{}}}, {}", name, first_reg, resolved))
            } else {
                (3, format!("{} {{v{}..v{}}}, {}", name, first_reg, first_reg + count as u16 - 1, resolved))
            }
        }

        // unop (12x)
        0x7b => (1, format!("neg-int v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x7c => (1, format!("not-int v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x7d => (1, format!("neg-long v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x7e => (1, format!("not-long v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x7f => (1, format!("neg-float v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x80 => (1, format!("neg-double v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x81 => (1, format!("int-to-long v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x82 => (1, format!("int-to-float v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x83 => (1, format!("int-to-double v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x84 => (1, format!("long-to-int v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x85 => (1, format!("long-to-float v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x86 => (1, format!("long-to-double v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x87 => (1, format!("float-to-int v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x88 => (1, format!("float-to-long v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x89 => (1, format!("float-to-double v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x8a => (1, format!("double-to-int v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x8b => (1, format!("double-to-long v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x8c => (1, format!("double-to-float v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x8d => (1, format!("int-to-byte v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x8e => (1, format!("int-to-char v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),
        0x8f => (1, format!("int-to-short v{}, v{}", reg_a(bc, pc), reg_b(bc, pc))),

        // binop (23x)
        0x90..=0xaf => {
            let names = [
                "add-int", "sub-int", "mul-int", "div-int", "rem-int",
                "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
                "add-long", "sub-long", "mul-long", "div-long", "rem-long",
                "and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
                "add-float", "sub-float", "mul-float", "div-float", "rem-float",
                "add-double", "sub-double", "mul-double", "div-double", "rem-double",
            ];
            let name = names[(op - 0x90) as usize];
            let aa = reg_aa(bc, pc);
            let cc = bc.get(pc + 2).copied().unwrap_or(0);
            let dd = bc.get(pc + 3).copied().unwrap_or(0);
            (2, format!("{} v{}, v{}, v{}", name, aa, cc, dd))
        }

        // binop/2addr (12x)
        0xb0..=0xcf => {
            let names = [
                "add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr", "rem-int/2addr",
                "and-int/2addr", "or-int/2addr", "xor-int/2addr", "shl-int/2addr", "shr-int/2addr", "ushr-int/2addr",
                "add-long/2addr", "sub-long/2addr", "mul-long/2addr", "div-long/2addr", "rem-long/2addr",
                "and-long/2addr", "or-long/2addr", "xor-long/2addr", "shl-long/2addr", "shr-long/2addr", "ushr-long/2addr",
                "add-float/2addr", "sub-float/2addr", "mul-float/2addr", "div-float/2addr", "rem-float/2addr",
                "add-double/2addr", "sub-double/2addr", "mul-double/2addr", "div-double/2addr", "rem-double/2addr",
            ];
            let name = names[(op - 0xb0) as usize];
            (1, format!("{} v{}, v{}", name, reg_a(bc, pc), reg_b(bc, pc)))
        }

        // binop/lit16 (22s)
        0xd0..=0xd7 => {
            let names = [
                "add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16",
                "rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16",
            ];
            let name = names[(op - 0xd0) as usize];
            let lit = i16_at(bc, pc + 2);
            (2, format!("{} v{}, v{}, #{}", name, reg_a(bc, pc), reg_b(bc, pc), lit))
        }

        // binop/lit8 (22b)
        0xd8..=0xe2 => {
            let names = [
                "add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
                "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8",
                "shl-int/lit8", "shr-int/lit8", "ushr-int/lit8",
            ];
            let name = names[(op - 0xd8) as usize];
            let cc = bc.get(pc + 2).copied().unwrap_or(0);
            let lit = bc.get(pc + 3).copied().unwrap_or(0) as i8;
            (2, format!("{} v{}, v{}, #{}", name, reg_aa(bc, pc), cc, lit))
        }

        // Default: unknown opcode  - use format width table
        _ => {
            let width = opcode_width(op);
            (width, format!("unknown_{:02x}", op))
        }
    }
}

/// Decode register list for invoke-kind (35c format).
fn decode_invoke_regs(bc: &[u8], pc: usize, count: u8) -> String {
    if count == 0 {
        return String::new();
    }
    // Register encoding for 35c:
    // Word at pc+4: D|C|F|G encoded as [G:4|F:4] at byte pc+4, [D:4|C:4] at byte pc+5
    // Actually: pc+4 has DCFG nibbles in a specific order
    // Byte pc+4: bits 0-3 = C, bits 4-7 = D
    // Byte pc+5: bits 0-3 = E, bits 4-7 = F
    // The A register is encoded in bits 4-7 of pc+1 (which is reg_b)
    // Actual encoding per spec:
    // A|G|BBBB|F|E|D|C
    // pc+0: op
    // pc+1: A (hi nibble) | G (lo nibble)  - but G is count, A is extra reg
    // Actually for 35c: the "B" in the second byte is the argument count
    // So: pc+1 hi=count, pc+1 lo=reg_g   - Wait, I need to be more careful.
    //
    // 35c format: A|G|op  BBBB  F|E|D|C
    // Byte layout: [op, A<<4|G, BBBB_lo, BBBB_hi, D<<4|C, F<<4|E]
    // A = arg count (in hi nibble of byte 1)
    // BBBB = method index
    // C,D,E,F,G = register args (G only if count == 5)

    let c = bc.get(pc + 4).map(|b| b & 0x0F).unwrap_or(0);
    let d = bc.get(pc + 4).map(|b| (b >> 4) & 0x0F).unwrap_or(0);
    let e = bc.get(pc + 5).map(|b| b & 0x0F).unwrap_or(0);
    let f = bc.get(pc + 5).map(|b| (b >> 4) & 0x0F).unwrap_or(0);
    let g = reg_a(bc, pc); // lo nibble of byte 1

    let regs = [c, d, e, f, g];
    let mut parts = Vec::new();
    for i in 0..(count as usize).min(5) {
        parts.push(format!("v{}", regs[i]));
    }
    parts.join(", ")
}

/// Width in code units for opcodes not explicitly handled.
/// Based on the Dalvik instruction format table.
fn opcode_width(op: u8) -> u32 {
    match op {
        // 10x, 11x, 11n, 12x formats  - 1 code unit
        0x00..=0x01 | 0x04 | 0x07 | 0x0a..=0x12 | 0x1d..=0x1e | 0x21 | 0x27..=0x28
        | 0x7b..=0x8f | 0xb0..=0xcf => 1,

        // 20t, 21s, 21h, 21c, 22x, 22b, 22t, 22s, 22c, 23x formats  - 2 code units
        0x02 | 0x05 | 0x08 | 0x13 | 0x15..=0x16 | 0x19..=0x1a | 0x1c | 0x1f..=0x20
        | 0x22..=0x23 | 0x29 | 0x2d..=0x3d | 0x44..=0x6d | 0x90..=0xaf | 0xd0..=0xe2 => 2,

        // 30t, 31i, 31t, 31c, 32x, 35c, 3rc formats  - 3 code units
        0x03 | 0x06 | 0x09 | 0x14 | 0x17 | 0x1b | 0x24..=0x26 | 0x2a..=0x2c
        | 0x6e..=0x72 | 0x74..=0x78 => 3,

        // 51l  - 5 code units
        0x18 => 5,

        // Everything else: assume 2 (most common width)
        _ => 2,
    }
}
