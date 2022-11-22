//! Library to parse stack usage information ([`.stack_sizes`]) produced by LLVM
//!
//! [`.stack_sizes`]: https://llvm.org/docs/CodeGenerator.html#emitting-function-stack-size-information

#![deny(rust_2018_idioms)]
// #![deny(missing_docs)]
// #![deny(warnings)]

#[macro_use]
extern crate failure;

use core::u16;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Cursor,
};
#[cfg(feature = "tools")]
use std::{fs, path::Path};

use byteorder::{ReadBytesExt, LE};
use xmas_elf::{
    header,
    sections::SectionData,
    symbol_table::{Entry, Type},
    ElfFile,
};

use llvm_ir::debugloc::HasDebugLoc;
use llvm_ir::module::Module;
use llvm_ir_analysis::{CallGraph, ModuleAnalysis};

/// Functions found after analyzing an executable
#[derive(Clone, Debug)]
pub struct Functions<'a> {
    /// Whether the addresses of these functions are 32-bit or 64-bit
    pub have_32_bit_addresses: bool,

    /// "undefined" symbols, symbols that need to be dynamically loaded
    pub undefined: HashSet<&'a str>,

    /// "defined" symbols, symbols with known locations (addresses)
    pub defined: BTreeMap<u64, Function<'a>>,
}

/// A symbol that represents a function (subroutine)
#[derive(Clone, Debug)]
pub struct Function<'a> {
    names: Vec<&'a str>,
    size: u64,
    stack: Option<u64>,
}

impl<'a> Function<'a> {
    /// Returns the (mangled) name of the function and its aliases
    pub fn names(&self) -> &[&'a str] {
        &self.names
    }

    /// Returns the size of this subroutine in bytes
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the stack usage of the function in bytes
    pub fn stack(&self) -> Option<u64> {
        self.stack
    }
}

// is this symbol a tag used to delimit code / data sections within a subroutine?
fn is_tag(name: &str) -> bool {
    name == "$a" || name == "$t" || name == "$d" || {
        (name.starts_with("$a.") || name.starts_with("$d.") || name.starts_with("$t."))
            && name.split_once('.').unwrap().1.parse::<u64>().is_ok()
    }
}

fn process_symtab_obj<'a, E>(
    entries: &'a [E],
    elf: &ElfFile<'a>,
) -> Result<
    (
        BTreeMap<u16, BTreeMap<u64, HashSet<&'a str>>>,
        BTreeMap<u32, u16>,
    ),
    failure::Error,
>
where
    E: Entry,
{
    let mut names: BTreeMap<_, BTreeMap<_, HashSet<_>>> = BTreeMap::new();
    let mut shndxs = BTreeMap::new();

    for (entry, i) in entries.iter().zip(0..) {
        let name = entry.get_name(elf);
        let shndx = entry.shndx();
        let addr = entry.value() & !1; // clear the thumb bit
        let ty = entry.get_type();

        if shndx != 0 {
            shndxs.insert(i, shndx);
        }

        if ty == Ok(Type::Func)
            || (ty == Ok(Type::NoType)
                && name
                    .map(|name| !name.is_empty() && !is_tag(name))
                    .unwrap_or(false))
        {
            let name = name.map_err(failure::err_msg)?;

            names
                .entry(shndx)
                .or_default()
                .entry(addr)
                .or_default()
                .insert(name);
        }
    }

    Ok((names, shndxs))
}

/// Parses an *input* (AKA relocatable) object file (`.o`) and returns a list of symbols and their
/// stack usage
pub fn analyze_object(obj: &[u8]) -> Result<HashMap<&str, u64>, failure::Error> {
    let elf = &ElfFile::new(obj).map_err(failure::err_msg)?;

    if elf.header.pt2.type_().as_type() != header::Type::Relocatable {
        bail!("object file is not relocatable")
    }

    // shndx -> (address -> [symbol-name])
    let mut is_64_bit = false;
    let (shndx2names, symtab2shndx) = match elf
        .find_section_by_name(".symtab")
        .ok_or_else(|| failure::err_msg("`.symtab` section not found"))?
        .get_data(elf)
    {
        Ok(SectionData::SymbolTable32(entries)) => process_symtab_obj(entries, elf)?,

        Ok(SectionData::SymbolTable64(entries)) => {
            is_64_bit = true;
            process_symtab_obj(entries, elf)?
        }

        _ => bail!("malformed .symtab section"),
    };

    let mut sizes = HashMap::new();
    let mut sections = elf.section_iter();
    while let Some(section) = sections.next() {
        if section.get_name(elf) == Ok(".stack_sizes") {
            let mut stack_sizes = Cursor::new(section.raw_data(elf));

            // next section should be `.rel.stack_sizes` or `.rela.stack_sizes`
            // XXX should we check the section name?
            let relocs: Vec<_> = match sections
                .next()
                .and_then(|section| section.get_data(elf).ok())
            {
                Some(SectionData::Rel32(rels)) if !is_64_bit => rels
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                Some(SectionData::Rela32(relas)) if !is_64_bit => relas
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                Some(SectionData::Rel64(rels)) if is_64_bit => rels
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                Some(SectionData::Rela64(relas)) if is_64_bit => relas
                    .iter()
                    .map(|rel| rel.get_symbol_table_index())
                    .collect(),

                _ => bail!("expected a section with relocation information after `.stack_sizes`"),
            };

            for index in relocs {
                let addr = if is_64_bit {
                    stack_sizes.read_u64::<LE>()?
                } else {
                    u64::from(stack_sizes.read_u32::<LE>()?)
                };
                let stack = leb128::read::unsigned(&mut stack_sizes).unwrap();

                let shndx = symtab2shndx[&index];
                let entries = shndx2names
                    .get(&(shndx as u16))
                    .unwrap_or_else(|| panic!("section header with index {} not found", shndx));

                assert!(sizes
                    .insert(
                        *entries
                            .get(&addr)
                            .unwrap_or_else(|| panic!(
                                "symbol with address {} not found at section {} ({:?})",
                                addr, shndx, entries
                            ))
                            .iter()
                            .next()
                            .unwrap(),
                        stack
                    )
                    .is_none());
            }

            if stack_sizes.position() != stack_sizes.get_ref().len() as u64 {
                bail!(
                    "the number of relocations doesn't match the number of `.stack_sizes` entries"
                );
            }
        }
    }

    Ok(sizes)
}

fn process_symtab_exec<'a, E>(
    entries: &'a [E],
    elf: &ElfFile<'a>,
) -> Result<
    (HashSet<&'a str>, BTreeMap<u64, Function<'a>>, Option<u64>),
    failure::Error,
>
where
    E: Entry + core::fmt::Debug,
{
    let mut defined = BTreeMap::new();
    let mut maybe_aliases = BTreeMap::new();
    let mut undefined = HashSet::new();
    let mut canary = None;

    for entry in entries {
        let ty = entry.get_type();
        let value = entry.value();
        let size = entry.size();
        let name = entry.get_name(elf);

        if ty == Ok(Type::Func) {
            let name = name.map_err(failure::err_msg)?;

            if value == 0 && size == 0 {
                undefined.insert(name);
            } else {
                defined
                    .entry(value)
                    .or_insert(Function {
                        names: vec![],
                        size,
                        stack: None,
                    })
                    .names
                    .push(name);
            }
        } else if name == Ok("app_stack_canary") {
            println!("CANARY FOUND: {:?}", value);
            canary = Some(value);
        } else if ty == Ok(Type::NoType) {
            if let Ok(name) = name {
                if !is_tag(name) {
                    maybe_aliases.entry(value).or_insert(vec![]).push(name);
                }
            }
        }

        println!("NAME: {:?}", name)
    }

    for (value, alias) in maybe_aliases {
        // try with the thumb bit both set and clear
        if let Some(sym) = defined.get_mut(&(value | 1)) {
            sym.names.extend(alias);
        } else if let Some(sym) = defined.get_mut(&(value & !1)) {
            sym.names.extend(alias);
        }
    }

    Ok((undefined, defined, canary))
}

/// Parses an executable ELF file and returns a list of functions and their stack usage
pub fn analyze_executable(elf: &[u8]) -> Result<(Functions<'_>, Option<u64>), failure::Error> {
    let elf = &ElfFile::new(elf).map_err(failure::err_msg)?;

    let mut have_32_bit_addresses = false;
    let (undefined, mut defined, canary) =
        if let Some(section) = elf.find_section_by_name(".symtab") {
            match section.get_data(elf).map_err(failure::err_msg)? {
                SectionData::SymbolTable32(entries) => {
                    have_32_bit_addresses = true;

                    process_symtab_exec(entries, elf)?
                }

                SectionData::SymbolTable64(entries) => process_symtab_exec(entries, elf)?,
                _ => bail!("malformed .symtab section"),
            }
        } else {
            (HashSet::new(), BTreeMap::new(), None)
        };

    if let Some(stack_sizes) = elf.find_section_by_name(".stack_sizes") {
        let data = stack_sizes.raw_data(elf);
        let end = data.len() as u64;
        let mut cursor = Cursor::new(data);

        while cursor.position() < end {
            let address = if have_32_bit_addresses {
                u64::from(cursor.read_u32::<LE>()?)
            } else {
                cursor.read_u64::<LE>()?
            };
            let stack = leb128::read::unsigned(&mut cursor)?;

            // NOTE try with the thumb bit both set and clear
            if let Some(sym) = defined.get_mut(&(address | 1)) {
                sym.stack = Some(stack);
            } else if let Some(sym) = defined.get_mut(&(address & !1)) {
                sym.stack = Some(stack);
            } else {
                unreachable!()
            }
        }
    }

    println!("Canary is {:?}", canary);

    Ok((
        Functions {
            have_32_bit_addresses,
            defined,
            undefined,
        },
        canary,
    ))
}

fn get_stack_height_and_path(
    stack_sizes: &HashMap<&str, u64>,
    call_graph: &CallGraph<'_>,
    name: &str,
    seen: &mut HashSet<String>,
) -> Option<Vec<(u64, u64, String)>> {
    let stack = stack_sizes.get(name).unwrap();
    if seen.contains(name) {
        println!("Loop in call graph: at {:#?} {:#?}", name, seen);
        None
    } else {
        let sname = String::from(name);
        seen.insert(sname.clone());
        let mut max_path = if !sname.contains("TrampolinedFuture") {
            call_graph
                .callers(name)
                .map(|name| get_stack_height_and_path(stack_sizes, call_graph, name, seen))
                .max_by(|x, y| match x {
                    None => std::cmp::Ordering::Greater,
                    Some(x) => match y {
                        None => std::cmp::Ordering::Less,
                        Some(y) => x.last().unwrap().1.cmp(&y.last().unwrap().1),
                    },
                })
                .unwrap_or(Some(Vec::new()))?
        } else {
            get_stack_height_and_path(stack_sizes, call_graph, "handle_fut_trampoline", seen)?
        };
        seen.remove(&sname);
        max_path.push((
            *stack,
            stack + max_path.last().unwrap_or(&(0, 0, String::new())).1,
            String::from(name),
        ));
        Some(max_path)
    }
}

#[cfg(feature = "tools")]
#[doc(hidden)]
pub fn run_exec(exec: &Path, obj: &Path) -> Result<(), failure::Error> {
    let module_file = obj.with_extension("bc");
    let exec = &fs::read(exec)?;
    let obj = &fs::read(obj)?;
    let module = Module::from_bc_path(module_file).map_err(failure::err_msg)?;
    let module_analysis = ModuleAnalysis::new(&module);
    let call_graph = module_analysis.call_graph();

    let stack_sizes = analyze_object(obj)?;
    let (symbols, canary) = analyze_executable(exec)?;

    let mut maximum_stack = None;

    if symbols.have_32_bit_addresses {
        // 32-bit address space
        println!("address\t\tstack\tmax stack height\tname\tline number\tcallers");

        /*println!("digraph {{");
        println!("node[shape=record];");*/

        for (addr, sym) in symbols.defined {
            let stack = sym
                .names()
                .iter()
                .filter_map(|name| stack_sizes.get(name))
                .next();

            if let (Some(name), Some(stack)) = (sym.names().first(), stack) {
                let _callees: Vec<String> = call_graph.callees(name).map(String::from).collect();
                let callers: Vec<String> = call_graph.callers(name).map(String::from).collect();
                let max_backtrace =
                    get_stack_height_and_path(&stack_sizes, &call_graph, name, &mut HashSet::new());
                let stack_height = max_backtrace.as_ref().map(|a| a.last().unwrap().1);

                if stack_height > maximum_stack {
                    maximum_stack = stack_height;
                }

                /*
                println!("{}[label=\"{{{}|{:?}}}\"];", name, rustc_demangle::demangle(name), stack_height);
                for caller in callers {
                    println!("{} -> {};", caller, name);
                }
                */

                println!(
                    "{:#010x}\t{}\t{:?}\t{}\t{:?}\t{:?}",
                    addr,
                    stack,
                    stack_height,
                    rustc_demangle::demangle(name),
                    module
                        .get_func_by_name(name)
                        .unwrap()
                        .get_debug_loc()
                        .as_ref()
                        .map(|a| a.line),
                    callers
                );
                match max_backtrace {
                    Some(max_backtrace) => {
                        println!("Tallest Backtrace\nframe size\tstack size\tname");
                        for (frame, stack, name) in max_backtrace.iter() {
                            println!("{}\t{}\t{}", frame, stack, name);
                        }
                        println!();
                    }
                    None => {}
                }
                /*println!(
                    "CALLEES: {:?}", callees);
                println!(
                    "CALLERS: {:?}", callers);
                println!(
                    "LINE: {:?}", module.get_func_by_name(name).unwrap().get_debug_loc());*/
            }
        }
        println!("}}");
    } else {
        // 64-bit address space
        println!("address\t\t\tstack\tname");

        for (addr, sym) in symbols.defined {
            let stack = sym
                .names()
                .iter()
                .filter_map(|name| stack_sizes.get(name))
                .next();

            if let (Some(name), Some(stack)) = (sym.names().first(), stack) {
                println!(
                    "{:#018x}\t{}\t{}",
                    addr,
                    stack,
                    rustc_demangle::demangle(name)
                );
                let callees: Vec<String> = call_graph.callees(name).map(String::from).collect();
                println!("CALLEES: {:?}", callees);
            }
        }
    }

    let canary_size = canary.map(|a| a & 0xffffff);

    let maximum_total = maximum_stack.zip(canary_size).map(|(a, b)| a + b);
    println!(
        "Maximum stack: {:?}\nGlobals: {:?}\nTotal memory: {:?}\n",
        maximum_stack, canary_size, maximum_total
    );
    let stack_limit = 4500;
    match maximum_stack {
        Some(m) if m > stack_limit => {
            failure::bail!("Used too much stack: {} > {}", m, stack_limit)
        }
        _ => {}
    }

    Ok(())
}

#[cfg(feature = "tools")]
#[doc(hidden)]
pub fn run(path: &Path) -> Result<(), failure::Error> {
    let bytes = &fs::read(path)?;
    let elf = &ElfFile::new(bytes).map_err(failure::err_msg)?;

    if elf.header.pt2.type_().as_type() == header::Type::Relocatable {
        let symbols = analyze_object(bytes)?;

        if symbols.is_empty() {
            bail!("this object file contains no stack usage information");
        }

        println!("stack\tname");
        for (name, stack) in symbols {
            println!("{}\t{}", stack, rustc_demangle::demangle(name));
        }

        Ok(())
    } else {
        let (symbols, _) = analyze_executable(bytes)?;

        if symbols
            .defined
            .values()
            .all(|symbol| symbol.stack().is_none())
        {
            bail!("this executable contains no stack usage information");
        }

        if symbols.have_32_bit_addresses {
            // 32-bit address space
            println!("address\t\tstack\tname");

            for (addr, sym) in symbols.defined {
                if let (Some(name), Some(stack)) = (sym.names().first(), sym.stack()) {
                    println!(
                        "{:#010x}\t{}\t{}",
                        addr,
                        stack,
                        rustc_demangle::demangle(name)
                    );
                }
            }
        } else {
            // 64-bit address space
            println!("address\t\t\tstack\tname");

            for (addr, sym) in symbols.defined {
                if let (Some(name), Some(stack)) = (sym.names().first(), sym.stack()) {
                    println!(
                        "{:#018x}\t{}\t{}",
                        addr,
                        stack,
                        rustc_demangle::demangle(name)
                    );
                }
            }
        }

        Ok(())
    }
}
