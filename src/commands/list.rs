use crate::error::Result;
use crate::store;

pub fn execute() -> Result<()> {
    let vault = store::read_vault()?;
    let (data, _) = store::open_vault(&vault)?;

    for (key, value) in &data {
        println!("{key}={value}");
    }

    Ok(())
}
