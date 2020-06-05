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

fn offset(i: &[u8]) -> IResult<&[u8], isize> {
    let (i, data) = number(i)?;
    let sign = if (data & 1) == 1 { -1 } else { 1 };
    let offset = ((data >> 1) as isize) * sign;
    Ok((i, offset))
}

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

fn source_read_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    if action_id != 0 {
        return Err(tag_error(i));
    }
    Ok((i, Action::SourceRead { length }))
}

fn target_read_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    let (i, data) = take(length)(i)?;
    if action_id != 1 {
        return Err(tag_error(i));
    }
    Ok((i, Action::TargetRead { data: data.into() }))
}

fn source_copy_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    if action_id != 2 {
        return Err(tag_error(i));
    }
    let (i, offset) = offset(i)?;
    Ok((i, Action::SourceCopy { length, offset }))
}

fn target_copy_action(i: &[u8]) -> IResult<&[u8], Action> {
    let (i, (action_id, length)) = action_header(i)?;
    if action_id != 3 {
        return Err(tag_error(i));
    }
    let (i, offset) = offset(i)?;
    Ok((i, Action::TargetCopy { length, offset }))
}

pub fn parse_bps(i: &[u8]) -> IResult<&[u8], Patch> {
    let (i, _) = tag("BPS1")(i)?;
    let (i, source_size) = number(i)?;
    let (i, target_size) = number(i)?;
    let (i, metadata_size) = number(i)?;
    let (i, metadata_bytes) = take(metadata_size as usize)(i)?;

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
