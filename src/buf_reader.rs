use crate::{
    error::{Error, Result},
    file,
};
use std::{
    fs::File,
    io::{self, prelude::*},
    rc::Rc,
};

#[derive(Debug)]
pub struct BufReader {
    reader: io::BufReader<File>,
    buf: Rc<String>,
}

fn new_buf() -> Rc<String> {
    Rc::new(String::with_capacity(file::CHUNK_SIZE as usize))
}

impl BufReader {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let file = File::open(path).map_err(Error::from)?;
        let reader = io::BufReader::new(file);
        let buf = new_buf();

        Ok(Self { reader, buf })
    }
}

impl Iterator for BufReader {
    type Item = io::Result<Rc<String>>;

    fn next(&mut self) -> Option<Self::Item> {
        let buf = match Rc::get_mut(&mut self.buf) {
            Some(buf) => {
                buf.clear();
                buf
            }
            None => {
                self.buf = new_buf();
                Rc::make_mut(&mut self.buf)
            }
        };

        self.reader
            .by_ref()
            .take(file::CHUNK_SIZE.into())
            .read_to_string(buf)
            .map(|u| {
                if u == 0 {
                    None
                } else {
                    Some(Rc::clone(&self.buf))
                }
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const PATH: &str = "test/lorem_ipsum";
    fn contents() -> String {
        fs::read_to_string(PATH).unwrap()
    }

    #[test]
    fn buf_reader_creates_chunks() {
        let mut reader = BufReader::open(PATH).unwrap();
        let mut count = 0;

        while let Some(_) = reader.next() {
            count += 1;
        }

        assert_eq!(count, contents().len().div_ceil(file::CHUNK_SIZE as usize));
    }

    #[test]
    fn buf_reader_reads_correct_data() {
        let mut reader = BufReader::open(PATH).unwrap();
        let mut data = String::new();

        while let Some(line) = reader.next() {
            let line = line.unwrap();
            data.push_str(&line);
        }

        assert_eq!(data, contents());
    }
}
