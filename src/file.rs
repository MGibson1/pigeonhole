#![allow(dead_code)]

use crate::buf_reader::BufReader;
use crate::error::{Error, Result};
use sha2::Digest;

#[cfg(not(test))]
pub(crate) const CHUNK_SIZE: u64 = 1024;
#[cfg(test)]
pub(crate) const CHUNK_SIZE: u64 = 8;

#[derive(Debug, Clone)]
pub(crate) struct File {
    manifest: FileManifest,
    path: String,
}

impl File {
    pub fn open(path: &str) -> Result<Self> {
        Ok(Self {
            manifest: FileManifest::new(),
            path: path.to_owned(),
        })
    }

    pub fn guess_num_chunks(&self) -> Result<u64> {
        Ok(std::fs::File::open(&self.path)
            .map_err(Error::from)?
            .metadata()
            .map_err(Error::from)?
            .len()
            .div_ceil(CHUNK_SIZE))
    }

    pub fn chunk(&mut self) -> Result<Vec<FileChunk>> {
        let mut chunks = Vec::new();

        // Iteration here also updates manifest
        for chunk in self.iter()? {
            chunks.push(chunk?);
        }

        Ok(chunks)
    }

    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    pub fn iter(&mut self) -> Result<FileIterator> {
        Ok(FileIterator {
            buf_reader: BufReader::open(&self.path)?,
            file: self,
        })
    }
}

pub(crate) struct FileChunk {
    buffer: Vec<u8>,
}

impl FileChunk {
    fn new(buf: &str) -> Self {
        Self {
            buffer: Vec::from(buf.as_bytes()),
        }
    }
    fn content_id(&self) -> [u8; 32] {
        sha2::Sha256::digest(&self.buffer).into()
    }

    fn to_string(&self) -> Result<String> {
        Ok(String::from_utf8(self.buffer.clone())?)
    }
}

pub(crate) struct FileIterator<'a> {
    file: &'a mut File,
    buf_reader: BufReader,
}

impl Iterator for FileIterator<'_> {
    type Item = Result<FileChunk>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.buf_reader.next() {
            Some(Ok(buf)) => {
                // TODO Encrypt the buffer prior cid calculation and return
                let chunk = FileChunk::new(&buf);
                self.file.manifest.add(&chunk);
                Some(Ok(chunk))
            }
            Some(Err(e)) => Some(Err(Error::from(e))),
            None => {
                self.file.manifest.mark_complete();
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileManifest {
    content_ids: Vec<[u8; 32]>,
    complete: bool,
}

impl FileManifest {
    fn new() -> Self {
        Self {
            content_ids: vec![],
            complete: false,
        }
    }

    fn add(&mut self, chunk: &FileChunk) {
        self.content_ids.push(chunk.content_id());
    }

    fn mark_complete(&mut self) {
        self.complete = true;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const PATH: &str = "test/lorem_ipsum";

    #[test]
    fn guess_num_chunks() {
        assert_eq!(File::open(PATH).unwrap().guess_num_chunks().unwrap(), 10);
    }

    #[test]
    fn chunk_contains_all_data() {
        let contents = std::fs::read_to_string(PATH).unwrap();
        let chunks = File::open(PATH).unwrap().chunk().unwrap();
        assert_eq!(
            contents,
            chunks
                .iter()
                .map(|c| c.to_string().unwrap())
                .collect::<Vec<_>>()
                .join("")
        )
    }

    #[test]
    fn chunk_updates_manifest() {
        let mut file = File::open(PATH).unwrap();
        let chunks = file.chunk().unwrap();
        assert_eq!(file.manifest.content_ids.len(), 10);

        for (pos, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.content_id(), file.manifest.content_ids[pos])
        }

        assert!(file.manifest.complete);
    }

    #[test]
    fn iter() {
        let mut file = File::open(PATH).unwrap();
        let mut cids: Vec<[u8; 32]> = Vec::new();

        for chunk in file.iter().unwrap() {
            let chunk = chunk.unwrap();
            cids.push(chunk.content_id());
        }
        assert_eq!(file.manifest().content_ids, cids);
        assert!(file.manifest().complete);
    }
}
