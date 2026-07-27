//! Layer fixtures, generated rather than committed.
//!
//! A malicious tar checked into the repository is unreviewable — nobody diffs
//! 512-byte header blocks — and it is exactly the shape of fixture this project
//! has been burned by before: one that no longer represents the input it is
//! named for, while the suite stays green. Building each layer here keeps the
//! adversarial intent readable in the same file as the assertion.
//!
//! Names are written into the header **verbatim**, because the `tar` crate's
//! `Header::set_path` refuses absolute paths and `..` — the two shapes several
//! of these fixtures exist to produce. [`super::tests::the_fixture_builder_writes_the_name_it_was_given`]
//! reads every awkward name back through the same parser the extractor uses, so
//! a fixture cannot quietly stop containing the attack it is named for.

use std::io::Read;
use tar::{Builder, EntryType, Header};

/// One layer tar, assembled in memory.
pub struct Layer(Builder<Vec<u8>>);

impl Layer {
    pub fn new() -> Self {
        Self(Builder::new(Vec::new()))
    }

    /// The finished tar bytes.
    pub fn done(self) -> Vec<u8> {
        self.0.into_inner().expect("finish tar")
    }

    /// Append an entry with the name and link target written into the header
    /// exactly as given.
    fn raw<R: Read>(
        &mut self,
        name: &[u8],
        link: &[u8],
        kind: EntryType,
        mode: u32,
        size: u64,
        data: R,
    ) -> &mut Self {
        assert!(
            name.len() <= 100,
            "fixture names stay in the ustar name field"
        );
        assert!(link.len() <= 100, "fixture link targets stay in the header");
        let mut h = Header::new_gnu();
        {
            let g = h.as_gnu_mut().expect("gnu header");
            g.name[..name.len()].copy_from_slice(name);
            g.linkname[..link.len()].copy_from_slice(link);
        }
        h.set_mode(mode);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_entry_type(kind);
        h.set_size(size);
        h.set_cksum();
        self.0.append(&h, data).expect("append");
        self
    }

    pub fn file(&mut self, name: &str, mode: u32, data: &[u8]) -> &mut Self {
        self.raw(
            name.as_bytes(),
            b"",
            EntryType::Regular,
            mode,
            data.len() as u64,
            data,
        )
    }

    /// A file whose name is arbitrary bytes — non-UTF-8, control characters.
    pub fn raw_file(&mut self, name: &[u8], data: &[u8]) -> &mut Self {
        self.raw(
            name,
            b"",
            EntryType::Regular,
            0o644,
            data.len() as u64,
            data,
        )
    }

    pub fn dir(&mut self, name: &str, mode: u32) -> &mut Self {
        self.raw(name.as_bytes(), b"", EntryType::Directory, mode, 0, &[][..])
    }

    pub fn symlink(&mut self, name: &str, target: &str) -> &mut Self {
        self.raw(
            name.as_bytes(),
            target.as_bytes(),
            EntryType::Symlink,
            0o777,
            0,
            &[][..],
        )
    }

    pub fn hardlink(&mut self, name: &str, target: &str) -> &mut Self {
        self.raw(
            name.as_bytes(),
            target.as_bytes(),
            EntryType::Link,
            0o644,
            0,
            &[][..],
        )
    }

    /// A character/block device or FIFO entry.
    pub fn node(&mut self, name: &str, kind: EntryType) -> &mut Self {
        self.raw(name.as_bytes(), b"", kind, 0o600, 0, &[][..])
    }

    /// An entry declaring `len` bytes of zeros, streamed rather than buffered —
    /// the compression bomb, which only costs what the extractor lets it write.
    pub fn zeros(&mut self, name: &str, len: u64) -> &mut Self {
        self.raw(
            name.as_bytes(),
            b"",
            EntryType::Regular,
            0o644,
            len,
            std::io::repeat(0).take(len),
        )
    }

    /// A whiteout marker: an ordinary empty file whose *name* is the
    /// instruction. Spelled out here so the fixtures read the way a layer does.
    pub fn whiteout(&mut self, name: &str) -> &mut Self {
        self.file(name, 0o644, b"")
    }

    /// A file preceded by a PAX extended header carrying `SCHILY.xattr.*`
    /// records — how a real archiver stores extended attributes.
    pub fn file_with_xattrs(
        &mut self,
        name: &str,
        data: &[u8],
        xattrs: &[(&str, &str)],
    ) -> &mut Self {
        let mut pax = Vec::new();
        for (k, v) in xattrs {
            pax.extend_from_slice(&pax_record(
                format!("SCHILY.xattr.{k}").as_bytes(),
                v.as_bytes(),
            ));
        }
        self.raw(
            b"PaxHeaders/x",
            b"",
            EntryType::XHeader,
            0o644,
            pax.len() as u64,
            &pax[..],
        );
        self.file(name, 0o644, data)
    }

    /// A file whose name arrives in a PAX `path=` record, overriding a benign
    /// name in the ustar header.
    ///
    /// This is the only way some hostile names can reach a parser at all: the
    /// ustar name field is NUL-terminated, so a NUL is truncated away before
    /// anything sees it. It is also where a writer and a parser can disagree —
    /// if the extractor validated the ustar name and wrote the PAX one, every
    /// check in this crate would be looking at the wrong string.
    pub fn pax_path_file(&mut self, path: &[u8], data: &[u8]) -> &mut Self {
        let rec = pax_record(b"path", path);
        self.raw(
            b"PaxHeaders/p",
            b"",
            EntryType::XHeader,
            0o644,
            rec.len() as u64,
            &rec[..],
        );
        self.raw(
            b"ustar-name-that-must-not-be-used",
            b"",
            EntryType::Regular,
            0o644,
            data.len() as u64,
            data,
        )
    }
}

/// One PAX record: `"<len> <key>=<value>\n"`, where `<len>` counts the whole
/// record **including the digits that spell it** — so the length is solved for
/// rather than measured.
fn pax_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    let body_len = key.len() + 1 + value.len() + 1;
    let mut len = body_len + 2;
    while format!("{len} ").len() + body_len != len {
        len += 1;
    }
    let mut out = format!("{len} ").into_bytes();
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// gzip a layer, so a bomb fixture can prove the byte counter sits on the
/// **decompressed** side of the stream rather than on the declared size.
pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(bytes).expect("gzip");
    e.finish().expect("gzip finish")
}
