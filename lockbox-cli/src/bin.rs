pub mod opt;
use dirs::home_dir;
use lockbox::error::Error;
use lockbox::Lockbox;
use opt::Opt;
use std::path::PathBuf;
use structopt::StructOpt;

const DEFAULT_LOCKBOX_NAME: &str = "lockbox";

pub fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    match opt {
        Opt::New(command) => {
            let path = get_filename(command.name.as_deref())?;
            Lockbox::create(&path, &command.master_password)?;
            Ok(())
        }

        Opt::Add(command) => {
            let path = get_filename(command.name.as_deref())?;
            let mut lockbox = Lockbox::load(&path, &command.master_password)?;
            lockbox.add_password(
                command.url,
                command.username,
                command.password,
                command.notes,
            )?;
            Ok(())
        }

        Opt::Edit(command) => {
            let path = get_filename(command.name.as_deref())?;
            let mut lockbox = Lockbox::load(&path, &command.master_password)?;
            lockbox.edit_password(
                command.id,
                command.url,
                command.username,
                command.password,
                command.notes,
            )
        }

        Opt::Decrypt(command) => {
            let path = get_filename(command.name.as_deref())?;
            let mut lockbox = Lockbox::load(&path, &command.master_password)?;
            let decrypted_password = lockbox.find_password_by_id(&command.id).unwrap();
            println!(
                "{}, {}, {}, {}, {}",
                decrypted_password.id,
                decrypted_password.url,
                decrypted_password.username,
                decrypted_password.password,
                decrypted_password.notes
            );
            Ok(())
        }

        Opt::List(command) => {
            let path = get_filename(command.name.as_deref())?;
            let lockbox = Lockbox::load(&path, &command.master_password)?;
            let passwords = lockbox.get_encrypted_passwords();

            for password in passwords {
                println!(
                    "{}, {}, {}",
                    &password.id, &password.url, &password.username
                );
            }

            Ok(())
        }
    }
}

fn get_filename(name: Option<&str>) -> Result<PathBuf, Error> {
    let filename = format!("{}.protob", name.unwrap_or(DEFAULT_LOCKBOX_NAME));
    home_dir()
        .map(|dir| dir.join("lockbox").join(filename))
        .ok_or(Error::new_invalid_data_error(
            "Error: could not find home directory",
        ))
}
