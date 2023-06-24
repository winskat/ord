use {
  super::*,
  bitcoin::{
    blockdata::{
      opcodes,
      script::{self, Instruction, Instructions},
    },
    util::taproot::TAPROOT_ANNEX_PREFIX,
    Script, Witness,
  },
  std::{iter::Peekable, str},
};

const INSCRIPTION_ENVELOPE_HEADER: [bitcoin::blockdata::script::Instruction<'static>; 3] = [
  Instruction::PushBytes(&[]), // This is an OP_FALSE
  Instruction::Op(opcodes::all::OP_IF),
  Instruction::PushBytes(PROTOCOL_ID),
];
const PROTOCOL_ID: &[u8] = b"ord";
const BODY_TAG: &[u8] = &[];
const CONTENT_TYPE_TAG: &[u8] = &[1];
const CURSED_TAG: &[u8] = &[66];

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum Curse {
  NotInFirstInput,
  NotAtOffsetZero,
  Reinscription,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Inscription {
  body: Option<Vec<u8>>,
  content_type: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TransactionInscription {
  pub(crate) inscription: Inscription,
  pub(crate) tx_in_index: u32,
  pub(crate) tx_in_offset: u32,
}

impl Inscription {
  #[cfg(test)]
  pub(crate) fn new(content_type: Option<Vec<u8>>, body: Option<Vec<u8>>) -> Self {
    Self { content_type, body }
  }

  pub(crate) fn from_transaction(tx: &Transaction) -> Vec<TransactionInscription> {
    let mut result = Vec::new();
    for (index, tx_in) in tx.input.iter().enumerate() {
      let Ok(inscriptions) = InscriptionParser::parse(&tx_in.witness) else { continue };

      result.extend(
        inscriptions
          .into_iter()
          .enumerate()
          .map(|(offset, inscription)| TransactionInscription {
            inscription,
            tx_in_index: u32::try_from(index).unwrap(),
            tx_in_offset: u32::try_from(offset).unwrap(),
          })
          .collect::<Vec<TransactionInscription>>(),
      )
    }

    result
  }

  pub(crate) fn from_witness(witness: &Witness) -> Result<Vec<Inscription>> {
    InscriptionParser::parse(witness)
  }

  pub(crate) fn from_file(chain: Chain, path: impl AsRef<Path>) -> Result<Self, Error> {
    let path = path.as_ref();

    let body = fs::read(path).with_context(|| format!("io error reading {}", path.display()))?;

    if let Some(limit) = chain.inscription_content_size_limit() {
      let len = body.len();
      if len > limit {
        bail!("content size of {len} bytes exceeds {limit} byte limit for {chain} inscriptions");
      }
    }

    let content_type = Media::content_type_for_path(path)?;

    Ok(Self {
      body: Some(body),
      content_type: Some(content_type.into()),
    })
  }

  fn append_reveal_script_to_builder(&self, mut builder: script::Builder, cursed: bool) -> script::Builder {
    builder = builder
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(PROTOCOL_ID);

    if let Some(content_type) = &self.content_type {
      builder = builder
        .push_slice(CONTENT_TYPE_TAG)
        .push_slice(content_type);
    }

    if cursed {
      log::info!("Appending cursed tag");
      builder = builder
        .push_slice(CURSED_TAG)
        .push_slice("cursed".as_bytes());
    }

    if let Some(body) = &self.body {
      builder = builder.push_slice(BODY_TAG);
      for chunk in body.chunks(520) {
        builder = builder.push_slice(chunk);
      }
    }

    builder.push_opcode(opcodes::all::OP_ENDIF)
  }

  pub(crate) fn append_reveal_script(&self, builder: script::Builder, cursed: bool) -> Script {
    self.append_reveal_script_to_builder(builder, cursed).into_script()
  }

  pub(crate) fn media(&self) -> Media {
    if self.body.is_none() {
      return Media::Unknown;
    }

    let Some(content_type) = self.content_type() else {
      return Media::Unknown;
    };

    content_type.parse().unwrap_or(Media::Unknown)
  }

  pub(crate) fn body(&self) -> Option<&[u8]> {
    Some(self.body.as_ref()?)
  }

  pub(crate) fn into_body(self) -> Option<Vec<u8>> {
    self.body
  }

  pub(crate) fn content_length(&self) -> Option<usize> {
    Some(self.body()?.len())
  }

  pub(crate) fn content_type(&self) -> Option<&str> {
    str::from_utf8(self.content_type.as_ref()?).ok()
  }

  #[cfg(test)]
  pub(crate) fn to_witness(&self) -> Witness {
    let builder = script::Builder::new();

    let script = self.append_reveal_script(builder, false);

    let mut witness = Witness::new();

    witness.push(script);
    witness.push([]);

    witness
  }
}

#[derive(Debug, PartialEq)]
pub(crate) enum InscriptionError {
  EmptyWitness,
  InvalidInscription,
  KeyPathSpend,
  NoInscription,
  Script(script::Error),
  UnrecognizedEvenField,
}

type Result<T, E = InscriptionError> = std::result::Result<T, E>;

struct InscriptionParser<'a> {
  instructions: Peekable<Instructions<'a>>,
}

impl<'a> InscriptionParser<'a> {
  fn parse(witness: &Witness) -> Result<Vec<Inscription>> {
    if witness.is_empty() {
      return Err(InscriptionError::EmptyWitness);
    }

    if witness.len() == 1 {
      return Err(InscriptionError::KeyPathSpend);
    }

    let annex = witness
      .last()
      .and_then(|element| element.first().map(|byte| *byte == TAPROOT_ANNEX_PREFIX))
      .unwrap_or(false);

    if witness.len() == 2 && annex {
      return Err(InscriptionError::KeyPathSpend);
    }

    let script = witness
      .iter()
      .nth(if annex {
        witness.len() - 1
      } else {
        witness.len() - 2
      })
      .unwrap();

    InscriptionParser {
      instructions: Script::from(Vec::from(script)).instructions().peekable(),
    }
    .parse_inscriptions()
    .into_iter()
    .collect()
  }

  fn parse_inscriptions(&mut self) -> Vec<Result<Inscription>> {
    let mut inscriptions = Vec::new();
    loop {
      let current = self.parse_one_inscription();
      if current == Err(InscriptionError::NoInscription) {
        break;
      }
      inscriptions.push(current);
    }

    inscriptions
  }

  fn parse_one_inscription(&mut self) -> Result<Inscription> {
    self.advance_into_inscription_envelope()?;

    let mut fields = BTreeMap::new();

    loop {
      match self.advance()? {
        Instruction::PushBytes(BODY_TAG) => {
          let mut body = Vec::new();
          while !self.accept(&Instruction::Op(opcodes::all::OP_ENDIF))? {
            body.extend_from_slice(self.expect_push()?);
          }
          fields.insert(BODY_TAG, body);
          break;
        }
        Instruction::PushBytes(tag) => {
          if fields.contains_key(tag) {
            return Err(InscriptionError::InvalidInscription);
          }
          fields.insert(tag, self.expect_push()?.to_vec());
        }
        Instruction::Op(opcodes::all::OP_ENDIF) => break,
        _ => return Err(InscriptionError::InvalidInscription),
      }
    }

    let body = fields.remove(BODY_TAG);
    let content_type = fields.remove(CONTENT_TYPE_TAG);

    for tag in fields.keys() {
      if let Some(lsb) = tag.first() {
        if lsb % 2 == 0 {
          return Err(InscriptionError::UnrecognizedEvenField);
        }
      }
    }

    Ok(Inscription { body, content_type })
  }

  fn advance(&mut self) -> Result<Instruction<'a>> {
    self
      .instructions
      .next()
      .ok_or(InscriptionError::NoInscription)?
      .map_err(InscriptionError::Script)
  }

  fn advance_into_inscription_envelope(&mut self) -> Result<()> {
    loop {
      if self.match_instructions(&INSCRIPTION_ENVELOPE_HEADER)? {
        break;
      }
    }

    Ok(())
  }

  fn match_instructions(&mut self, instructions: &[Instruction]) -> Result<bool> {
    for instruction in instructions {
      if &self.advance()? != instruction {
        return Ok(false);
      }
    }

    Ok(true)
  }

  fn expect_push(&mut self) -> Result<&'a [u8]> {
    match self.advance()? {
      Instruction::PushBytes(bytes) => Ok(bytes),
      _ => Err(InscriptionError::InvalidInscription),
    }
  }

  fn accept(&mut self, instruction: &Instruction) -> Result<bool> {
    match self.instructions.peek() {
      Some(Ok(next)) => {
        if next == instruction {
          self.advance()?;
          Ok(true)
        } else {
          Ok(false)
        }
      }
      Some(Err(err)) => Err(InscriptionError::Script(*err)),
      None => Ok(false),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty() {
    assert_eq!(
      InscriptionParser::parse(&Witness::new()),
      Err(InscriptionError::EmptyWitness)
    );
  }

  #[test]
  fn ignore_key_path_spends() {
    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![Vec::new()])),
      Err(InscriptionError::KeyPathSpend),
    );
  }

  #[test]
  fn ignore_key_path_spends_with_annex() {
    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![Vec::new(), vec![0x50]])),
      Err(InscriptionError::KeyPathSpend),
    );
  }

  #[test]
  fn ignore_unparsable_scripts() {
    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![vec![0x01], Vec::new()])),
      Err(InscriptionError::Script(script::Error::EarlyEndOfScript)),
    );
  }

  #[test]
  fn no_inscription() {
    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![
        Script::new().into_bytes(),
        Vec::new()
      ])),
      Ok(vec![])
    );
  }

  #[test]
  fn duplicate_field() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[
        b"ord",
        &[1],
        b"text/plain;charset=utf-8",
        &[1],
        b"text/plain;charset=utf-8",
        &[],
        b"ord",
      ])),
      Err(InscriptionError::InvalidInscription),
    );
  }

  #[test]
  fn valid() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[
        b"ord",
        &[1],
        b"text/plain;charset=utf-8",
        &[],
        b"ord",
      ])),
      Ok(vec![inscription("text/plain;charset=utf-8", "ord")]),
    );
  }

  #[test]
  fn valid_with_unknown_tag() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[
        b"ord",
        &[1],
        b"text/plain;charset=utf-8",
        &[3],
        b"bar",
        &[],
        b"ord",
      ])),
      Ok(vec![inscription("text/plain;charset=utf-8", "ord")]),
    );
  }

  #[test]
  fn no_content_tag() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[b"ord", &[1], b"text/plain;charset=utf-8"])),
      Ok(vec![Inscription {
        content_type: Some(b"text/plain;charset=utf-8".to_vec()),
        body: None,
      }]),
    );
  }

  #[test]
  fn no_content_type() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[b"ord", &[], b"foo"])),
      Ok(vec![Inscription {
        content_type: None,
        body: Some(b"foo".to_vec()),
      }]),
    );
  }

  #[test]
  fn valid_body_in_multiple_pushes() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[
        b"ord",
        &[1],
        b"text/plain;charset=utf-8",
        &[],
        b"foo",
        b"bar"
      ])),
      Ok(vec![inscription("text/plain;charset=utf-8", "foobar")]),
    );
  }

  #[test]
  fn valid_body_in_zero_pushes() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[b"ord", &[1], b"text/plain;charset=utf-8", &[]])),
      Ok(vec![inscription("text/plain;charset=utf-8", "")]),
    );
  }

  #[test]
  fn valid_body_in_multiple_empty_pushes() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[
        b"ord",
        &[1],
        b"text/plain;charset=utf-8",
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
      ])),
      Ok(vec![inscription("text/plain;charset=utf-8", "")]),
    );
  }

  #[test]
  fn valid_ignore_trailing() {
    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice(&[1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice(&[])
      .push_slice(b"ord")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::all::OP_CHECKSIG)
      .into_script();

    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![script.into_bytes(), Vec::new()])),
      Ok(vec![inscription("text/plain;charset=utf-8", "ord")]),
    );
  }

  #[test]
  fn valid_ignore_preceding() {
    let script = script::Builder::new()
      .push_opcode(opcodes::all::OP_CHECKSIG)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice(&[1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice(&[])
      .push_slice(b"ord")
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![script.into_bytes(), Vec::new()])),
      Ok(vec![inscription("text/plain;charset=utf-8", "ord")]),
    );
  }

  #[test]
  fn do_not_ignore_inscriptions_after_first() {
    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice(&[1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice(&[])
      .push_slice(b"foo")
      .push_opcode(opcodes::all::OP_ENDIF)
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice(b"ord")
      .push_slice(&[1])
      .push_slice(b"text/plain;charset=utf-8")
      .push_slice(&[])
      .push_slice(b"bar")
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![script.into_bytes(), Vec::new()])),
      Ok(vec![
        inscription("text/plain;charset=utf-8", "foo"),
        inscription("text/plain;charset=utf-8", "bar")
      ]),
    );
  }

  #[test]
  fn invalid_utf8_does_not_render_inscription_invalid() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[
        b"ord",
        &[1],
        b"text/plain;charset=utf-8",
        &[],
        &[0b10000000]
      ])),
      Ok(vec![inscription("text/plain;charset=utf-8", [0b10000000])]),
    );
  }

  #[test]
  fn no_endif() {
    let script = script::Builder::new()
      .push_opcode(opcodes::OP_FALSE)
      .push_opcode(opcodes::all::OP_IF)
      .push_slice("ord".as_bytes())
      .into_script();

    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![script.into_bytes(), Vec::new()])),
      Ok(vec![])
    );
  }

  #[test]
  fn no_op_false() {
    let script = script::Builder::new()
      .push_opcode(opcodes::all::OP_IF)
      .push_slice("ord".as_bytes())
      .push_opcode(opcodes::all::OP_ENDIF)
      .into_script();

    assert_eq!(
      InscriptionParser::parse(&Witness::from_vec(vec![script.into_bytes(), Vec::new()])),
      Ok(vec![])
    );
  }

  #[test]
  fn empty_envelope() {
    assert_eq!(InscriptionParser::parse(&envelope(&[])), Ok(vec![]));
  }

  #[test]
  fn wrong_magic_number() {
    assert_eq!(InscriptionParser::parse(&envelope(&[b"foo"])), Ok(vec![]));
  }

  #[test]
  fn extract_from_transaction() {
    let tx = Transaction {
      version: 0,
      lock_time: bitcoin::PackedLockTime(0),
      input: vec![TxIn {
        previous_output: OutPoint::null(),
        script_sig: Script::new(),
        sequence: Sequence(0),
        witness: envelope(&[b"ord", &[1], b"text/plain;charset=utf-8", &[], b"ord"]),
      }],
      output: Vec::new(),
    };

    assert_eq!(
      Inscription::from_transaction(&tx),
      vec![transaction_inscription(
        "text/plain;charset=utf-8",
        "ord",
        0,
        0
      )],
    );
  }

  #[test]
  fn extract_from_second_input() {
    let tx = Transaction {
      version: 0,
      lock_time: bitcoin::PackedLockTime(0),
      input: vec![
        TxIn {
          previous_output: OutPoint::null(),
          script_sig: Script::new(),
          sequence: Sequence(0),
          witness: Witness::new(),
        },
        TxIn {
          previous_output: OutPoint::null(),
          script_sig: Script::new(),
          sequence: Sequence(0),
          witness: inscription("foo", [1; 1040]).to_witness(),
        },
      ],
      output: Vec::new(),
    };

    assert_eq!(
      Inscription::from_transaction(&tx),
      vec![transaction_inscription("foo", [1; 1040], 1, 0)]
    );
  }

  #[test]
  fn extract_from_second_envelope() {
    let mut builder = script::Builder::new();
    builder = inscription("foo", [1; 100]).append_reveal_script_to_builder(builder, false);
    builder = inscription("bar", [1; 100]).append_reveal_script_to_builder(builder, false);

    let witness = Witness::from_vec(vec![builder.into_script().into_bytes(), Vec::new()]);

    let tx = Transaction {
      version: 0,
      lock_time: bitcoin::PackedLockTime(0),
      input: vec![TxIn {
        previous_output: OutPoint::null(),
        script_sig: Script::new(),
        sequence: Sequence(0),
        witness,
      }],
      output: Vec::new(),
    };

    assert_eq!(
      Inscription::from_transaction(&tx),
      vec![
        transaction_inscription("foo", [1; 100], 0, 0),
        transaction_inscription("bar", [1; 100], 0, 1)
      ]
    );
  }

  #[test]
  fn inscribe_png() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[b"ord", &[1], b"image/png", &[], &[1; 100]])),
      Ok(vec![inscription("image/png", [1; 100])]),
    );
  }

  #[test]
  fn reveal_script_chunks_data() {
    assert_eq!(
      inscription("foo", [])
        .append_reveal_script(script::Builder::new(), false)
        .instructions()
        .count(),
      7
    );

    assert_eq!(
      inscription("foo", [0; 1])
        .append_reveal_script(script::Builder::new(), false)
        .instructions()
        .count(),
      8
    );

    assert_eq!(
      inscription("foo", [0; 520])
        .append_reveal_script(script::Builder::new(), false)
        .instructions()
        .count(),
      8
    );

    assert_eq!(
      inscription("foo", [0; 521])
        .append_reveal_script(script::Builder::new(), false)
        .instructions()
        .count(),
      9
    );

    assert_eq!(
      inscription("foo", [0; 1040])
        .append_reveal_script(script::Builder::new(), false)
        .instructions()
        .count(),
      9
    );

    assert_eq!(
      inscription("foo", [0; 1041])
        .append_reveal_script(script::Builder::new(), false)
        .instructions()
        .count(),
      10
    );
  }

  #[test]
  fn chunked_data_is_parsable() {
    let mut witness = Witness::new();

    witness.push(&inscription("foo", [1; 1040]).append_reveal_script(script::Builder::new(), false));

    witness.push([]);

    assert_eq!(
      InscriptionParser::parse(&witness).unwrap(),
      vec![inscription("foo", [1; 1040])],
    );
  }

  #[test]
  fn round_trip_with_no_fields() {
    let mut witness = Witness::new();

    witness.push(
      &Inscription {
        content_type: None,
        body: None,
      }
      .append_reveal_script(script::Builder::new(), false),
    );

    witness.push([]);

    assert_eq!(
      InscriptionParser::parse(&witness).unwrap(),
      vec![Inscription {
        content_type: None,
        body: None,
      }]
    );
  }

  #[test]
  fn unknown_odd_fields_are_ignored() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[b"ord", &[3], &[0]])),
      Ok(vec![Inscription {
        content_type: None,
        body: None,
      }]),
    );
  }

  #[test]
  fn unknown_even_fields_are_invalid() {
    assert_eq!(
      InscriptionParser::parse(&envelope(&[b"ord", &[2], &[0]])),
      Err(InscriptionError::UnrecognizedEvenField),
    );
  }
}
