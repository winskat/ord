use {
  super::*,
  std::io::{BufRead, BufReader},
};

#[derive(Debug, Parser)]
pub(crate) struct Find {
  #[clap(long, help = "Only look in specified outpoint(s).")]
  outpoint: Vec<OutPoint>,
  #[clap(
    long,
    help = "Read a list of sats and ranges to find from a file. One sat or range per line. Ranges written as <start>-<end>."
  )]
  file: Vec<PathBuf>,
  #[clap(help = "Find output and offset of <SAT>.")]
  sat: Option<Sat>,
  #[clap(help = "Find output and offset of all sats in the range <SAT>-<END>.")]
  end: Option<Sat>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Output {
  pub satpoint: SatPoint,
}

impl Find {
  pub(crate) fn run(self, options: Options) -> Result {
    let index = Index::open(&options)?;

    index.update()?;

    let mut targets = Vec::new();
    let mut results = Vec::new();

    if let Some(sat) = self.sat {
      let end = match self.end {
        Some(end) => end,
        None => sat + 1,
      };

      if sat < end {
        targets.push((sat, end));
      } else {
        bail!("range is empty");
      }
    }

    let comment_re = Regex::new(r"#.*")?;
    for file in self.file {
      let reader = BufReader::new(File::open(&file)?);
      let mut line_number = 0;
      for line in reader.lines() {
        line_number += 1;
        let line = line?;
        let line = comment_re.replace(&line, "");
        let line = line.trim();
        if line.is_empty() {
          continue;
        }
        let mut split = line
          .trim_start_matches('\u{feff}')
          .split(&['-', '\u{2013}']); // ASCII hyphen or Unicode 'EN DASH'
        if let Some(start) = split.next() {
          let start = match start.parse() {
            Ok(start) => start,
            Err(err) => bail!(
              "parsing sat '{start}' on line {line_number} of '{:?}': {err}",
              file
            ),
          };

          let end = match split.next() {
            Some(end) => {
              if let Some(junk) = split.next() {
                bail!(
                  "trailing junk on line {line_number} of '{}' ({})",
                  file.display(),
                  junk
                );
              } else {
                match end.parse() {
                  Ok(end) => end,
                  Err(err) => bail!(
                    "parsing range end '{end}' on line {line_number} of '{:?}': {err}",
                    file
                  ),
                }
              }
            }
            None => start + 1,
          };
          targets.push((start, end));
        } else {
          bail!(
            "file '{}' is not formatted correctly at line {line_number}",
            file.display()
          );
        }
      }
    }

    if targets.is_empty() {
      bail!("nothing to find");
    }

    // loop through targets
    for (sat, end) in targets {
      match index.find(sat, end, &self.outpoint)? {
        Some(result) => results.extend(result),
        None => return Err(anyhow!("range has not been mined as of index height")),
      }
    }

    print_json(results)?;

    Ok(())
  }
}
