//! Native libraries bundled inside wheels and conda packages (#23).
//!
//! auditwheel, delocate and delvewheel copy the shared libraries a wheel links into the wheel
//! (`pillow.libs/libwebp-3a2b1c4d.so.7`, `PIL/.dylibs/libwebp.7.dylib`), where a tool that reads
//! package metadata never sees them: CVE-2023-4863 in the libwebp inside Pillow's wheels was
//! invisible that way. With `--prefix --embedded-sboms`, every file an installed package owns that is
//! named like a library in `data/signatures.toml` is opened, the library's version is read out of
//! it, and the library is attached as a [`PackageKind::Embedded`] component under the package that
//! ships it, with the CPE the CPE table gives it. An inventory of the libraries in the table, not of
//! everything a binary contains: the scanner decides what is vulnerable.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use object::{Object, ObjectSection, ObjectSymbol};
use serde::Deserialize;

use crate::embedded::{SOURCE_PROPERTY, source_path};
use crate::model::{Package, PackageKind, Sbom};
use crate::purl;

const TABLE: &str = include_str!("../data/signatures.toml");

/// What `pixi:embedded-sbom` says of a library found in a file.
const SOURCE_KIND: &str = "bundled";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    library: BTreeMap<String, Signature>,
}

/// How one library is recognized.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// The key of the library's entry in the CPE table.
    pub cpe: String,
    /// Conda packages that are the library itself.
    pub conda: Vec<String>,
    /// File name stems the library is installed as.
    pub files: Vec<String>,
    /// How its version is read.
    pub version: Extract,
}

/// Where in a file a library keeps its version.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Extract {
    /// The text after a fixed prefix.
    Text { prefix: String },
    /// The NUL-terminated string an exported symbol holds.
    Symbol { symbol: String },
    /// The NUL-terminated string an exported pointer points to.
    SymbolPointer {
        symbol: String,
        #[serde(default)]
        encoding: Encoding,
    },
    /// The constant an exported function returns, `major << 16 | minor << 8 | patch`.
    PackedFunction { symbol: String },
}

/// How a version string is spelled.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    /// As a version: `2.15.4`.
    #[default]
    Dotted,
    /// As `MMmmpp` digits: `21504`.
    Decimal,
}

/// Every library in the table, by name.
pub fn signatures() -> &'static BTreeMap<String, Signature> {
    static PARSED: std::sync::OnceLock<BTreeMap<String, Signature>> = std::sync::OnceLock::new();
    PARSED.get_or_init(|| {
        toml::from_str::<Table>(TABLE)
            .expect("data/signatures.toml is checked by its tests")
            .library
    })
}

/// The CPE table key of a bundled library component, by its name.
pub fn cpe_key(name: &str) -> Option<&'static str> {
    signatures().get(name).map(|s| s.cpe.as_str())
}

/// Whether a package is a library this module found bundled in a file.
pub fn is_bundled(package: &Package) -> bool {
    package.kind == PackageKind::Embedded
        && package
            .properties
            .get(SOURCE_PROPERTY)
            .is_some_and(|source| is_bundled_source(source))
}

/// Whether a `pixi:embedded-sbom` value names a bundled library, as a document read back records it.
pub fn is_bundled_source(source: &str) -> bool {
    source
        .strip_prefix(SOURCE_KIND)
        .is_some_and(|rest| rest.starts_with(':'))
}

/// Whether a file name is one the signature's library is installed as: a stem followed by
/// nothing, a `.` or a `-`/`_` (auditwheel's hash, a Windows ABI suffix).
fn names(signature: &Signature, file_name: &str) -> bool {
    signature.files.iter().any(|stem| {
        file_name
            .strip_prefix(stem.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '-', '_']))
    })
}

/// The library's version in a file's bytes, if the file is an object file that holds it.
pub fn version(signature: &Signature, bytes: &[u8]) -> Option<String> {
    match object::FileKind::parse(bytes).ok()? {
        object::FileKind::MachOFat32 => object::read::macho::MachOFatFile32::parse(bytes)
            .ok()?
            .arches()
            .iter()
            .find_map(|arch| version(signature, object::read::macho::FatArch::data(arch, bytes).ok()?)),
        object::FileKind::MachOFat64 => object::read::macho::MachOFatFile64::parse(bytes)
            .ok()?
            .arches()
            .iter()
            .find_map(|arch| version(signature, object::read::macho::FatArch::data(arch, bytes).ok()?)),
        _ => {
            let file = object::File::parse(bytes).ok()?;
            let found = match &signature.version {
                Extract::Text { prefix } => after(bytes, prefix.as_bytes()),
                Extract::Symbol { symbol } => {
                    let (address, section) = symbol_address(&file, symbol)?;
                    c_string(data_at(&file, address, section)?)
                }
                Extract::SymbolPointer { symbol, encoding } => {
                    let (address, section) = symbol_address(&file, symbol)?;
                    let (target, target_section) = pointer_at(&file, address, section)?;
                    let text = c_string(data_at(&file, target, target_section)?)?;
                    match encoding {
                        Encoding::Dotted => Some(text),
                        Encoding::Decimal => decimal(&text),
                    }
                }
                Extract::PackedFunction { symbol } => {
                    let (address, section) = symbol_address(&file, symbol)?;
                    let code = data_at(&file, address, section)?;
                    returned_constant(file.architecture(), code)
                        .map(|v| format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff))
                }
            };
            found.filter(|v| is_version(v))
        }
    }
}

/// `1.2.3`, `3.0.13`, `1.1.1w`: dotted numbers, the last of which may carry one letter.
fn is_version(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() >= 2
        && parts.iter().enumerate().all(|(i, part)| {
            let digits = part.trim_end_matches(|c: char| c.is_ascii_lowercase());
            let letters = part.len() - digits.len();
            !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && (letters == 0 || (letters == 1 && i == parts.len() - 1))
        })
}

/// The first version-shaped word after `prefix` in `bytes`.
fn after(bytes: &[u8], prefix: &[u8]) -> Option<String> {
    let mut start = 0;
    while let Some(at) = find(&bytes[start..], prefix) {
        let rest = &bytes[start + at + prefix.len()..];
        let word: Vec<u8> = rest
            .iter()
            .take(32)
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            .copied()
            .collect();
        if let Ok(word) = String::from_utf8(word)
            && is_version(&word)
        {
            return Some(word);
        }
        start += at + 1;
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A NUL-terminated string at the start of `data`.
fn c_string(data: &[u8]) -> Option<String> {
    let end = data.iter().take(64).position(|&b| b == 0)?;
    String::from_utf8(data[..end].to_vec()).ok()
}

/// `21504` as `2.15.4`.
fn decimal(text: &str) -> Option<String> {
    let n: u32 = text.parse().ok()?;
    Some(format!("{}.{}.{}", n / 10000, (n / 100) % 100, n % 100))
}

/// Where a symbol is, from the symbol table, the dynamic symbols or the export table, and the
/// section it is in when the file says. Mach-O spells C names with a leading underscore.
fn symbol_address(file: &object::File<'_>, name: &str) -> Option<(u64, Option<object::SectionIndex>)> {
    let underscored = format!("_{name}");
    let matches = |symbol: &[u8]| symbol == name.as_bytes() || symbol == underscored.as_bytes();
    file.symbols()
        .chain(file.dynamic_symbols())
        .find(|s| s.is_definition() && s.name_bytes().is_ok_and(matches))
        .map(|s| (s.address(), s.section_index()))
        .or_else(|| {
            file.exports()
                .ok()?
                .flatten()
                .find_map(|e| match (e.name(), e.target()) {
                    (object::NameOrOrdinal::Name(n), object::ExportTarget::Address { address }) if matches(n) => {
                        Some((address, None))
                    }
                    _ => None,
                })
        })
}

/// The file's bytes from `address` to the end of the section holding it. A relocatable object's
/// sections all start at zero, so the symbol's own section is asked first.
fn data_at<'data>(
    file: &object::File<'data>,
    address: u64,
    section: Option<object::SectionIndex>,
) -> Option<&'data [u8]> {
    let within = |s: &object::Section<'data, '_>| address >= s.address() && address - s.address() < s.size();
    let section = section
        .and_then(|index| file.section_by_index(index).ok())
        .filter(|s| within(s))
        .or_else(|| {
            file.sections()
                .find(|s| within(s) && s.data().is_ok_and(|d| !d.is_empty()))
        })?;
    let data = section.data().ok()?;
    data.get(usize::try_from(address - section.address()).ok()?..)
}

/// The address a pointer at `address` holds once the loader has relocated it: the dynamic
/// relocation an ELF shared library carries for it, the relocation an object file carries, or
/// the stored value, which in a Mach-O image with chained fixups keeps the target in its low 36
/// bits.
fn pointer_at(
    file: &object::File<'_>,
    address: u64,
    section: Option<object::SectionIndex>,
) -> Option<(u64, Option<object::SectionIndex>)> {
    if let Some(mut relocations) = file.dynamic_relocations()
        && let Some((_, relocation)) = relocations.find(|(offset, _)| *offset == address)
        && matches!(relocation.target(), object::RelocationTarget::Absolute)
    {
        return Some((u64::try_from(relocation.addend()).ok()?, None));
    }
    let data = data_at(file, address, section)?;
    let size = if file.is_64() { 8 } else { 4 };
    let raw = data.get(..size)?;
    let value = match (file.endianness(), size) {
        (object::Endianness::Little, 8) => u64::from_le_bytes(raw.try_into().ok()?),
        (object::Endianness::Big, 8) => u64::from_be_bytes(raw.try_into().ok()?),
        (object::Endianness::Little, _) => u64::from(u32::from_le_bytes(raw.try_into().ok()?)),
        (object::Endianness::Big, _) => u64::from(u32::from_be_bytes(raw.try_into().ok()?)),
    };
    if let Some(index) = section
        && let Ok(holder) = file.section_by_index(index)
        && let Some((_, relocation)) = holder
            .relocations()
            .find(|(offset, _)| holder.address() + offset == address)
    {
        let addend = if relocation.has_implicit_addend() {
            value as i64
        } else {
            relocation.addend()
        };
        let (base, target_section) = match relocation.target() {
            object::RelocationTarget::Symbol(target) => {
                let symbol = file.symbol_by_index(target).ok()?;
                (symbol.address(), symbol.section_index())
            }
            object::RelocationTarget::Section(target) => (file.section_by_index(target).ok()?.address(), Some(target)),
            _ => return None,
        };
        return Some((base.checked_add_signed(addend)?, target_section));
    }
    let held = |address: u64| data_at(file, address, None).is_some();
    [
        value,
        value & 0xf_ffff_ffff,
        (value & 0xf_ffff_ffff) + file.relative_address_base(),
    ]
    .into_iter()
    .find(|&candidate| candidate != 0 && held(candidate))
    .map(|candidate| (candidate, None))
}

/// The constant a function that only returns one leaves in the return register:
/// `mov eax, imm32; ret` on x86, `mov w0, #lo; movk w0, #hi, lsl #16; ret` on AArch64, after any
/// `endbr` / `bti` landing pad.
fn returned_constant(architecture: object::Architecture, code: &[u8]) -> Option<u32> {
    match architecture {
        object::Architecture::X86_64 | object::Architecture::I386 => {
            let code = code
                .strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa])
                .or_else(|| code.strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfb]))
                .unwrap_or(code);
            match code {
                [0xb8, a, b, c, d, 0xc3, ..] => Some(u32::from_le_bytes([*a, *b, *c, *d])),
                _ => None,
            }
        }
        object::Architecture::Aarch64 => {
            let words: Vec<u32> = code
                .as_chunks::<4>()
                .0
                .iter()
                .take(5)
                .map(|w| u32::from_le_bytes(*w))
                .collect();
            const BTI_C: u32 = 0xd503_245f;
            const RET: u32 = 0xd65f_03c0;
            let words = words.strip_prefix(&[BTI_C]).unwrap_or(&words);
            let movz = |w: u32| (w & 0xffe0_001f == 0x5280_0000).then_some((w >> 5) & 0xffff);
            let movk16 = |w: u32| (w & 0xffe0_001f == 0x72a0_0000).then_some(((w >> 5) & 0xffff) << 16);
            match words {
                [low, ret, ..] if *ret == RET => movz(*low),
                [low, high, ret, ..] if *ret == RET => Some(movz(*low)? | movk16(*high)?),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Counts from one pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Files named like a library that held its version.
    pub files: usize,
    /// Library components added.
    pub added: usize,
    /// Copies of a library version already added, found in another file.
    pub merged: usize,
}

/// Every file an installed package owns, relative to the prefix, with the package's index: a conda
/// record's `files`, and the `RECORD` of a pip-installed dist-info.
fn owned_files(sbom: &Sbom, prefix: &Path) -> Vec<(String, usize)> {
    let mut owned = Vec::new();
    let conda: HashMap<&str, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| matches!(p.kind, PackageKind::CondaBinary | PackageKind::CondaSource))
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();
    for (name, files) in crate::auditable::installed_files(prefix) {
        if let Some(&index) = conda.get(name.as_str()) {
            owned.extend(files.into_iter().map(|f| (f.replace('\\', "/"), index)));
        }
    }
    let pypi: HashMap<String, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.kind == PackageKind::Pypi)
        .map(|(i, p)| (purl::normalize_pypi_name(&p.name), i))
        .collect();
    for dist_info in crate::prefix::dist_infos(prefix) {
        let Some((name, _)) = crate::prefix::name_and_version(&dist_info) else {
            continue;
        };
        let (Some(&index), Some(site_packages)) = (pypi.get(&purl::normalize_pypi_name(&name)), dist_info.parent())
        else {
            continue;
        };
        let record = std::fs::read_to_string(dist_info.join("RECORD")).unwrap_or_default();
        for file in record.lines().filter_map(|line| line.split(',').next()) {
            if file.split(['/', '\\']).any(|part| part == "..") {
                continue;
            }
            if let Some(relative) = crate::prefix::relative_to(prefix, &site_packages.join(file)) {
                owned.push((relative, index));
            }
        }
    }
    owned.sort();
    owned.dedup();
    owned
}

/// Find the bundled libraries of an installed environment and attach each under the package
/// that ships it.
pub fn attach(sbom: &mut Sbom, prefix: &Path) -> Outcome {
    let mut outcome = Outcome::default();
    let mut by_id: HashMap<String, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id.clone(), i))
        .collect();
    for (relative, owner) in owned_files(sbom, prefix) {
        let file_name = relative.rsplit('/').next().unwrap_or(&relative);
        let owner_name = sbom.packages[owner].name.clone();
        let is_conda = sbom.packages[owner].kind != PackageKind::Pypi;
        let candidates: Vec<(&String, &Signature)> = signatures()
            .iter()
            .filter(|(_, s)| names(s, file_name))
            // A conda package that is the library holds the library, not a bundled copy of it.
            .filter(|(_, s)| !(is_conda && s.conda.contains(&owner_name)))
            .collect();
        if candidates.is_empty() {
            continue;
        }
        let Some(bytes) = crate::auditable::read_object(&prefix.join(&relative)) else {
            continue;
        };
        for (name, signature) in candidates {
            let Some(version) = version(signature, &bytes) else {
                tracing::debug!(file = %relative, library = %name, "named like the library, but no version in it");
                continue;
            };
            outcome.files += 1;
            let Ok(purl) = purl::generic(name, &version) else {
                continue;
            };
            let source = format!("{SOURCE_KIND}:{relative}");
            let index = match by_id.get(&purl) {
                Some(&existing) => {
                    outcome.merged += 1;
                    let package = &mut sbom.packages[existing];
                    let value = package.properties.entry(SOURCE_PROPERTY.to_string()).or_default();
                    if !value.split(';').any(|s| s == source) {
                        value.push(';');
                        value.push_str(&source);
                    }
                    package.add_occurrence(source_path(&source));
                    existing
                }
                None => {
                    by_id.insert(purl.clone(), sbom.packages.len());
                    sbom.packages.push(to_package(name, &version, &purl, &source));
                    outcome.added += 1;
                    sbom.packages.len() - 1
                }
            };
            let id = sbom.packages[index].id.clone();
            let deps = &mut sbom.packages[owner].dependencies;
            if !deps.contains(&id) {
                deps.push(id);
                deps.sort();
            }
        }
    }
    sbom.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    outcome
}

fn to_package(name: &str, version: &str, purl: &str, source: &str) -> Package {
    Package {
        id: purl.to_string(),
        name: name.to_string(),
        version: Some(version.to_string()),
        kind: PackageKind::Embedded,
        purl: purl.to_string(),
        supplier: None,
        extra_purls: Vec::new(),
        // The file is the authority on what it holds.
        purls_from_lock: true,
        location: String::new(),
        sha256: None,
        md5: None,
        sha512: None,
        license: None,
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties: BTreeMap::from([(SOURCE_PROPERTY.to_string(), source.to_string())]),
        dependencies: Vec::new(),
        occurrences: vec![source_path(source).to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{Object, Relocation, StandardSection, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind, SymbolFlags,
        SymbolKind, SymbolScope,
    };

    /// The three object file formats, each on the architecture a wheel for it is most often built for.
    const FORMATS: [(BinaryFormat, Architecture); 3] = [
        (BinaryFormat::Elf, Architecture::X86_64),
        (BinaryFormat::MachO, Architecture::Aarch64),
        (BinaryFormat::Coff, Architecture::X86_64),
    ];

    fn exported(name: &str, kind: SymbolKind) -> Symbol {
        Symbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        }
    }

    /// An object file holding what a library keeps its version in, as `extract` reads it.
    fn library(format: BinaryFormat, architecture: Architecture, extract: &Extract, version: &str) -> Vec<u8> {
        let mut object = Object::new(format, architecture, Endianness::Little);
        match extract {
            Extract::Text { prefix } => {
                let section = object.section_id(StandardSection::ReadOnlyData);
                // Something before it, and the text the library puts after the version.
                let text = format!("\0unrelated 9.9\0{prefix}{version} (and what follows)\0");
                object.append_section_data(section, text.as_bytes(), 1);
            }
            Extract::Symbol { symbol } => {
                let section = object.section_id(StandardSection::ReadOnlyData);
                let id = object.add_symbol(exported(symbol, SymbolKind::Data));
                object.add_symbol_data(id, section, format!("{version}\0").as_bytes(), 1);
            }
            Extract::SymbolPointer { symbol, encoding } => {
                let section = object.section_id(StandardSection::Data);
                let text = match encoding {
                    Encoding::Dotted => version.to_string(),
                    Encoding::Decimal => {
                        let parts: Vec<u32> = version.split('.').map(|p| p.parse().unwrap()).collect();
                        (parts[0] * 10000 + parts[1] * 100 + parts[2]).to_string()
                    }
                };
                let mut bytes = format!("{text}\0").into_bytes();
                bytes.resize(16, 0);
                let string_at = object.append_section_data(section, &bytes, 8);
                let pointer = object.add_symbol(exported(symbol, SymbolKind::Data));
                let pointer_at = object.add_symbol_data(pointer, section, &[0; 8], 8);
                let target = object.section_symbol(section);
                object
                    .add_relocation(
                        section,
                        Relocation {
                            offset: pointer_at,
                            symbol: target,
                            addend: string_at as i64,
                            flags: RelocationFlags::Generic {
                                kind: RelocationKind::Absolute,
                                encoding: RelocationEncoding::Generic,
                                size: 64,
                            },
                        },
                    )
                    .unwrap();
            }
            Extract::PackedFunction { symbol } => {
                let parts: Vec<u32> = version.split('.').map(|p| p.parse().unwrap()).collect();
                let value = parts[0] << 16 | parts[1] << 8 | parts[2];
                let code: Vec<u8> = match architecture {
                    // endbr64; mov eax, imm32; ret
                    Architecture::X86_64 => {
                        [&[0xf3, 0x0f, 0x1e, 0xfa, 0xb8][..], &value.to_le_bytes(), &[0xc3]].concat()
                    }
                    // bti c; mov w0, #lo; movk w0, #hi, lsl #16; ret
                    Architecture::Aarch64 => [
                        0xd503_245f,
                        0x5280_0000 | ((value & 0xffff) << 5),
                        0x72a0_0000 | ((value >> 16) << 5),
                        0xd65f_03c0,
                    ]
                    .iter()
                    .flat_map(|w: &u32| w.to_le_bytes())
                    .collect(),
                    other => panic!("{other:?}"),
                };
                let section = object.section_id(StandardSection::Text);
                let id = object.add_symbol(exported(symbol, SymbolKind::Text));
                object.add_symbol_data(id, section, &code, 16);
            }
        }
        object.write().unwrap()
    }

    /// Two upstream releases of each library, as each spells its version.
    const RELEASES: [(&str, [&str; 2]); 9] = [
        ("openssl", ["3.0.13", "1.1.1w"]),
        ("libwebp", ["1.3.1", "1.6.0"]),
        ("zlib", ["1.2.13", "1.3.1"]),
        ("sqlite", ["3.45.1", "3.50.4"]),
        ("libcurl", ["8.5.0", "8.15.0"]),
        ("libxml2", ["2.12.6", "2.15.1"]),
        ("expat", ["2.6.2", "2.7.1"]),
        ("libpng", ["1.6.39", "1.6.50"]),
        ("libjpeg-turbo", ["2.1.5", "3.1.1"]),
    ];

    #[test]
    fn every_library_s_version_is_read_out_of_every_format() {
        assert_eq!(
            RELEASES
                .iter()
                .map(|(name, _)| *name)
                .collect::<std::collections::BTreeSet<_>>(),
            signatures().keys().map(String::as_str).collect(),
            "a fixture for every library in the table"
        );
        for (name, versions) in RELEASES {
            let signature = &signatures()[name];
            for (format, architecture) in FORMATS {
                for wanted in versions {
                    let bytes = library(format, architecture, &signature.version, wanted);
                    assert_eq!(
                        version(signature, &bytes).as_deref(),
                        Some(wanted),
                        "{name} {wanted} in {format:?}"
                    );
                }
                let empty = Object::new(format, architecture, Endianness::Little).write().unwrap();
                assert_eq!(
                    version(signature, &empty),
                    None,
                    "{name}: nothing in an empty {format:?} file"
                );
            }
        }
        assert_eq!(
            version(&signatures()["zlib"], b"deflate 1.3.1 but not an object file"),
            None
        );
    }

    #[test]
    fn a_universal_binary_is_read_through_its_slices() {
        let signature = &signatures()["libwebp"];
        let slice = library(BinaryFormat::MachO, Architecture::Aarch64, &signature.version, "1.4.0");
        // fat_header and one fat_arch (big-endian), the slice at a page boundary.
        let mut fat = Vec::new();
        for word in [0xcafe_babe_u32, 1, 0x0100_000c, 0, 0x4000, slice.len() as u32, 14] {
            fat.extend(word.to_be_bytes());
        }
        fat.resize(0x4000, 0);
        fat.extend(&slice);
        assert_eq!(version(signature, &fat).as_deref(), Some("1.4.0"));
    }

    #[test]
    fn a_version_is_numbers_with_at_most_a_final_letter() {
        for good in ["1.2", "3.0.13", "1.1.1w", "2.15.4"] {
            assert!(is_version(good), "{good}");
        }
        for bad in [
            "1",
            "1.3.0.zlib",
            "1.3.0.zlib-ng",
            "v1.2",
            "1.2a.3",
            "1.2.3ab",
            "",
            "1..2",
        ] {
            assert!(!is_version(bad), "{bad}");
        }
        assert_eq!(decimal("21504").as_deref(), Some("2.15.4"));
        assert_eq!(decimal("20913").as_deref(), Some("2.9.13"));
        assert_eq!(decimal("not digits"), None);
        // zlib-ng's compatibility build calls itself zlib, but is not zlib's code.
        assert_eq!(after(b"deflate 1.3.0.zlib-ng Copyright", b"deflate "), None);
        assert_eq!(
            after(b"deflate stream\0deflate 1.3.1 Copyright", b"deflate "),
            Some("1.3.1".into())
        );
    }

    #[test]
    fn a_library_is_looked_for_only_in_files_named_like_it() {
        let webp = &signatures()["libwebp"];
        for name in [
            "libwebp.so.7",
            "libwebp-3a2b1c4d.so.7.1.8",
            "libwebp.7.dylib",
            "libwebp-7.dll",
            "libwebp",
        ] {
            assert!(names(webp, name), "{name}");
        }
        for name in ["libwebpmux.so.3", "libwebpdemux-1a2b.so.2", "webp.dll", "xlibwebp.so"] {
            assert!(!names(webp, name), "{name}");
        }
        let zlib = &signatures()["zlib"];
        assert!(names(zlib, "zlib1.dll"));
        assert!(!names(zlib, "libzstd.so.1"), "another library");
    }

    #[test]
    fn the_table_names_known_cpes_and_one_owner_per_package() {
        let mut owners = std::collections::BTreeMap::new();
        for (name, signature) in signatures() {
            assert!(
                crate::cpe::entry(&signature.cpe).is_some(),
                "{name}: {} is not in cpe.toml",
                signature.cpe
            );
            assert!(!signature.files.is_empty() && !signature.conda.is_empty(), "{name}");
            for conda in &signature.conda {
                assert_eq!(
                    owners.insert(conda.clone(), name.clone()),
                    None,
                    "{conda} is two libraries"
                );
            }
            assert_eq!(cpe_key(name), Some(signature.cpe.as_str()));
        }
        assert_eq!(cpe_key("not-a-library"), None);
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn bundled_copies_hang_off_the_package_that_ships_them() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path();
        let site = prefix.join("lib/python3.12/site-packages");
        let webp = |v: &str| {
            library(
                BinaryFormat::Elf,
                Architecture::X86_64,
                &signatures()["libwebp"].version,
                v,
            )
        };
        let zlib = library(
            BinaryFormat::Elf,
            Architecture::X86_64,
            &signatures()["zlib"].version,
            "1.3.1",
        );
        // Two wheels carry the same libwebp; one of them also an unrelated library and a file
        // named like libwebp that holds no version.
        for (dist, files) in [
            (
                "pillow",
                vec![
                    ("pillow.libs/libwebp-3a2b1c4d.so.7.1.8", webp("1.3.1")),
                    ("pillow.libs/libwebpmux-1a2b.so.3", webp("1.3.1")),
                    ("pillow.libs/libsharpyuv-9f8e.so.0", Vec::new()),
                ],
            ),
            (
                "imagecodecs",
                vec![("imagecodecs.libs/libwebp-77aa.so.7", webp("1.3.1"))],
            ),
            (
                "broken",
                vec![("broken.libs/libwebp-00.so.7", b"\x7fELF but truncated".to_vec())],
            ),
        ] {
            let dist_info = site.join(format!("{dist}-1.0.dist-info"));
            write(
                &dist_info.join("METADATA"),
                format!("Name: {dist}\nVersion: 1.0\n").as_bytes(),
            );
            let mut record = String::new();
            for (path, bytes) in files {
                write(&site.join(path), &bytes);
                record.push_str(&format!("{path},,\n"));
            }
            record.push_str("../../../bin/outside,,\n");
            write(&dist_info.join("RECORD"), record.as_bytes());
        }
        // A conda package that bundles zlib, and conda's own libzlib, which is zlib.
        write(&prefix.join("lib/libz.so.1"), &zlib);
        write(&prefix.join("opt/tool/lib/libz.so.1"), &zlib);
        for (name, file) in [("libzlib", "lib/libz.so.1"), ("tool", "opt/tool/lib/libz.so.1")] {
            write(
                &prefix.join(format!("conda-meta/{name}-1.0-0.json")),
                serde_json::json!({"name": name, "version": "1.0", "build": "0", "files": [file]})
                    .to_string()
                    .as_bytes(),
            );
        }
        let mut sbom = crate::prefix::build_sbom(prefix, crate::model::Root::default(), Some("linux-64")).unwrap();
        let outcome = attach(&mut sbom, prefix);
        assert_eq!(
            outcome,
            Outcome {
                files: 3,
                added: 2,
                merged: 1
            }
        );

        let find = |name: &str| sbom.packages.iter().find(|p| p.name == name).unwrap();
        let libwebp = find("libwebp");
        assert_eq!(libwebp.kind, PackageKind::Embedded);
        assert_eq!(libwebp.purl, "pkg:generic/libwebp@1.3.1");
        assert!(is_bundled(libwebp));
        assert_eq!(
            libwebp.occurrences,
            [
                "lib/python3.12/site-packages/imagecodecs.libs/libwebp-77aa.so.7",
                "lib/python3.12/site-packages/pillow.libs/libwebp-3a2b1c4d.so.7.1.8"
            ]
        );
        assert_eq!(
            crate::cpe::for_package(libwebp).as_deref(),
            Some("cpe:2.3:a:webmproject:libwebp:1.3.1:*:*:*:*:*:*:*")
        );
        for owner in ["pillow", "imagecodecs"] {
            assert!(find(owner).dependencies.contains(&libwebp.id), "{owner}");
        }
        assert!(!find("broken").dependencies.contains(&libwebp.id));
        let zlib = find("zlib");
        assert_eq!(
            zlib.occurrences,
            ["opt/tool/lib/libz.so.1"],
            "conda's libzlib is zlib, not a copy"
        );
        assert!(find("tool").dependencies.contains(&zlib.id));
        assert!(find("libzlib").dependencies.is_empty());
        assert!(!is_bundled(find("pillow")));
    }
}
