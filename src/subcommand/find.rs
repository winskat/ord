use super::*;

#[derive(Debug, Parser)]
pub(crate) struct Find {
  #[clap(long, help = "Only look in specified outpoint(s).")]
  outpoint: Vec<OutPoint>,
  #[clap(long, help = "Read a list of sats and ranges to find from a file. One sat or range per line. Ranges written as <start>-<end>.")]
  file: Option<PathBuf>,
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

    match self.sat {
      Some(sat) => {
        let end = match self.end {
          Some(end) => end,
          None => sat + 1,
        };

        if sat < end {
          match index.find(sat, end, &self.outpoint)? {
            Some(result) => {
              print_json(result)?;
              Ok(())
            }
            None => Err(anyhow!("range has not been mined as of index height")),
          }
        } else {
          Err(anyhow!("range is empty"))
        }
      }
      None => Err(anyhow!("no sat provided")),
    }
  }
}
