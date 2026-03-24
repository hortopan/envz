use crate::error::Result;
use crate::store;

pub fn execute() -> Result<()> {
    let vault = store::read_vault()?;
    let (data, _) = store::open_vault(&vault)?;

    for key in data.keys() {
        println!("unset {key}");
    }

    Ok(())
}
