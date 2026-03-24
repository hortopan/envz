use crate::error::Result;
use crate::store;

pub fn execute() -> Result<()> {
    let vault = store::read_vault()?;
    let (data, _) = store::open_vault(&vault)?;

    let mut keys: Vec<&str> = data.keys().map(|k| k.as_str()).collect();
    keys.sort();

    for key in keys {
        println!("{}={}", key, data[key]);
    }

    Ok(())
}
