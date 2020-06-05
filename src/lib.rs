// Comments contain text from the "BPS File Format Specification" by byuu
// licensed in the public domain/

use nom::{
    branch::alt,
    bytes::complete::{tag, take, take_till, take_while_m_n},
    error::{ErrorKind, ParseError},
    number::complete::le_u32,
    IResult,
};

#[derive(Debug)]
pub enum Action {
    SourceRead { length: usize },
    TargetRead { data: Vec<u8> },
    SourceCopy { length: usize, offset: isize },
    TargetCopy { length: usize, offset: isize },
}

#[derive(Debug)]
pub struct Patch {
    pub source_size: usize,
    pub target_size: usize,
    pub metadata: String,
    pub actions: Vec<Action>,
    pub source_checksum: u32,
    pub target_checksum: u32,
    pub patch_checksum: u32,
}

// Parse a variable-length encoded number
//
// From the spec:
//   Rather than limit the maximum file size supported to 16MB (24-bit) or
//   4GB (32-bit), beat patches use a variable-length encoding to support any
//   number of bits, and thus, any possible file size.
//
//   The basic idea is that we encode the lowest seven bits of the number, and
//   then the eighth bit of each byte is a flag to say whether the full number
//   has been represented or not. If set, this is the last byte of the number.
//   If not, then we shift out the low seven bits and repeat until the number
//   is fully encoded.
//
//   One last optimization is to subtract one after each encode. Without this,
//   one could encode '1' with 0x81 or 0x01 0x80, producing an ambiguity.
//
//   Decoding is the inverse of the above process.
fn number(i: &[u8]) -> IResult<&[u8], usize> {
    let (i, non_terminal_bytes) = take_till(|b| (b & 0x80) != 0)(i)?;
    let (i, terminal_byte) = take_while_m_n(1, 1, |b| (b & 0x80) != 0)(i)?;

    let mut data = 0;
    let mut shift = 0;
    for b in non_terminal_bytes.iter().chain(terminal_byte.iter()) {
        let mut val = (*b & 0x7f) as usize;
        if shift != 0 {
            val += 1;
        }

        val <<= shift;
        data += val;
        shift += 7;
    }
    Ok((i, data))
}

// Decode a relative offset
//
// From the spec:
//   beat patches keep track of the current file offsets in both the source and
//   target files separately. Reading from either increments their respective
//   offsets automatically.
//
//   As such, offsets are encoded relatively to the current positions. These
//   offsets can move the read cursors forward or backward. To support negative
//   numbers with variable-integer encoding requires us to store the negative
//   flag as the lowest bit, followed by the absolute value (eg abs(-1) = 1)
//
//   Note, and this is very important, for obvious reasons you cannot read from
//   before the start or after the end of the file. Further, you cannot read
//   beyond the current target write output offsets, as that data is not yet
//   available. Attempting to do so instantly makes the patch invalid and will
//   abort patching entirely.
fn offset(i: &[u8]) -> IResult<&[u8], isize> {
    let (i, data) = number(i)?;
    let sign = if (data & 1) == 1 { -1 } else { 1 };
    let offset = ((data >> 1) as isize) * sign;
    Ok((i, offset))
}

// Decode an action header.
//
// Every action begins with the same header.  The header is a variable-
// length encoded number.  The action_id and operand length are decoded
// as:
// * action_id: number & 0x3
// * length: (data >> 2) + 1
fn action_header(i: &[u8]) -> IResult<&[u8], (u8, usize)> {
    let (i, data) = number(i)?;
    let action = (data & 0x3) as u8;
    let length = (data >> 2) + 1;

    Ok((i, (action, length)))
}

fn tag_error<'a, Error: ParseError<&'a [u8]>>(i: &'a [u8]) -> nom::Err<Error> {
    let e: ErrorKind = ErrorKind::Tag;
    nom::Err::Error(Error::from_error_kind(i, e))
}

// decode a `SourceRead` action
//
// From the spec:
//   This command copies bytes from the source file to the target file. Since
//   both the patch creator and applier will have access to the entire source
//   file, the actual bytes to output do not need to be stored here.
//
//   This command is rarely useful in delta patch creation, and is mainly
//   intended to allow for linear-based patchers. However, at times it can be
//   useful even in delta patches when data is the same in both source and
//   target files at the same location.
fn source_read_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    if action_id != 0 {
        return Err(tag_error(i));
    }
    Ok((i, Action::SourceRead { length }))
}

// Decode a `TargetRead` action.
//
// From the spec:
//   When a file is modified, new data is thus created. This command can store
//   said data so that it can be written to the target file. This time, the
//   actual data is not available to the patch applier, so it is stored directly
//   inside the patch.
fn target_read_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    let (i, data) = take(length)(i)?;
    if action_id != 1 {
        return Err(tag_error(i));
    }
    Ok((i, Action::TargetRead { data: data.into() }))
}

// Decode a `SourceCopy` action.
//
// From the spec:
//   When a file is modified, new data is thus created. This command can store
//   said data so that it can be written to the target file. This time, the
//   actual data is not available to the patch applier, so it is stored directly
//   inside the patch.
fn source_copy_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    if action_id != 2 {
        return Err(tag_error(i));
    }
    let (i, offset) = offset(i)?;
    Ok((i, Action::SourceCopy { length, offset }))
}

// Decode a `TargetCopy` action.
//
// From the spec:
//   This command treats all of the data that has already been written to the
//   target file as a dictionary. By referencing already written data, we can
//   optimize repeated data in the target file that does not exist in the
//   source file.
//
//   This can allow for efficient run-length encoding. For instance, say 16MB of
//   0x00s appear in a row in only the target file. We can use TargetRead to
//   write a single 0x00. Now we can use TargetCopy to point at this byte, and
//   set the length to 16MB-1. The effect will be that the target output size
//   grows as the command runs, thus repeating the data.
fn target_copy_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    if action_id != 3 {
        return Err(tag_error(i));
    }
    let (i, offset) = offset(i)?;
    Ok((i, Action::TargetCopy { length, offset }))
}

// Parase a BPS patch.
pub fn parse_bps(i: &[u8]) -> IResult<&[u8], Patch> {
    // From the spec:
    //   First, we have the file format marker, "BPS1". We then encode the
    //   source and target file sizes. Next, we encode optional metadata. If no
    //   metadata is present, store an encoded zero here (0x80 per above.)
    //   Otherwise, specify the length of the metadata.

    //   Note that officially, metadata should be XML version 1.0 encoding
    //   UTF-8 data, and the metadata-size specifies the actual length. As in,
    //   there is no null-terminator after the metadata. However, the actual
    //   contents here are entirely domain-specific, so literally anything can
    //   go here and the patch will still be considered valid.
    //
    // ```
    //   string "BPS1"
    //   number source-size
    //   number target-size
    //   number metadata-size
    //   string metadata[metadata-size]
    // ```
    let (i, _) = tag("BPS1")(i)?;
    let (i, source_size) = number(i)?;
    let (i, target_size) = number(i)?;
    let (i, metadata_size) = number(i)?;
    let (i, metadata_bytes) = take(metadata_size as usize)(i)?;

    // From the spec:
    //   Commands repeat until the end of the patch. This can be detected by
    //   testing the patch read location, and stopping when
    //   `offset() >= size() - 12`. Where 12 is the number of bytes in the
    //   patch footer.
    //
    // ```
    //   repeat {
    //     number action | ((length - 1) << 2)
    //     action 0: SourceRead {
    //   }
    //   action 1: TargetRead {
    //     byte[] length
    //   }
    //   action 2: SourceCopy {
    //     number negative | (abs(offset) << 1)
    //   }
    //   action 3: TargetCopy {
    //     number negative | (abs(offset) << 1)
    //   }
    // }
    let mut i = i;
    let mut actions = Vec::new();
    while i.len() > 12 {
        let (ai, action) = alt((
            source_read_action,
            target_read_action,
            source_copy_action,
            target_copy_action,
        ))(i)?;
        actions.push(action);
        i = ai;
    }

    // Read the checksums in the footer.
    let (i, source_checksum) = le_u32(i)?;
    let (i, target_checksum) = le_u32(i)?;
    let (i, patch_checksum) = le_u32(i)?;

    Ok((
        i,
        Patch {
            source_size,
            target_size,
            metadata: String::from_utf8_lossy(&metadata_bytes).into(),
            actions,
            source_checksum,
            target_checksum,
            patch_checksum,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn it_works() {
        let bps_data =
            fs::read("src/test-data/FF4FE.bBAABAAAAAAAAAFCPAgAAACAQIKAsAEo.PNMX9BQDFZ.bps")
                .unwrap();
        let (_, _) = parse_bps(&bps_data).unwrap();
    }

    #[test]
    fn decode_number() {
        assert_eq!(number(&[0x80]), Ok((&[][..], 0usize)));
        assert_eq!(number(&[0x82]), Ok((&[][..], 2)));
        assert_eq!(number(&[0xff]), Ok((&[][..], 0x7f)));
        assert_eq!(number(&[0x00, 0x80]), Ok((&[][..], 0x80)));
    }
}
