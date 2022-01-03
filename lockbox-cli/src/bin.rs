pub mod import;
pub mod opt;
use dirs::home_dir;
use import::{Importer, LastPassRecord};
use lockbox::error::Error;
use lockbox::Lockbox;
use opt::Opt;
use std::path::PathBuf;
use structopt::StructOpt;

pub fn main() -> Result<(), Error> {
    let opt = Opt::from_args();
    match opt {
        Opt::New(command) => {
            let path = get_lockbox_filename(command.name.as_deref())?;
            Lockbox::create(&path, &command.master_password)?;
            Ok(())
        }

        Opt::ImportLastPass(command) => {
            let path = get_lockbox_filename(command.name.as_deref())?;
            let mut lockbox = Lockbox::create(&path, &command.master_password)?;
            LastPassRecord::import(&command.file, &mut lockbox).unwrap();
            Ok(())
        }

        Opt::Add(command) => {
            let path = get_lockbox_filename(command.name.as_deref())?;
            let mut lockbox = Lockbox::load(&path, &command.master_password)?;
            lockbox.add_password(
                command.url,
                command.username,
                command.password,
                command.notes,
            )?;

            lockbox.save()
        }

        Opt::Edit(command) => {
            let path = get_lockbox_filename(command.name.as_deref())?;
            let mut lockbox = Lockbox::load(&path, &command.master_password)?;
            lockbox.edit_password(
                command.id,
                command.url,
                command.username,
                command.password,
                command.notes,
            )?;

            lockbox.save()
        }

        Opt::Get(command) => {
            let path = get_lockbox_filename(command.name.as_deref())?;
            let mut lockbox = Lockbox::load(&path, &command.master_password)?;
            let passwords = lockbox.find_passwords(|p| {
                command.id.as_ref().map_or(true, |id| p.id.eq(id))
                    && command.url.as_ref().map_or(true, |url| p.url.contains(url))
                    && command
                        .username
                        .as_ref()
                        .map_or(true, |username| p.username.contains(username))
            });

            for password in passwords {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    password.id,
                    password.url.split("?").next().unwrap(),
                    password.username,
                    password.password,
                    password.notes
                );
            }

            Ok(())
        }

        Opt::List(command) => {
            let path = get_lockbox_filename(command.name.as_deref())?;
            let lockbox = Lockbox::load(&path, &command.master_password)?;
            let passwords = lockbox.get_encrypted_passwords();

            for password in passwords {
                println!(
                    "{}\t{}\t{}",
                    &password.id,
                    &password.url.split("?").next().unwrap(),
                    &password.username
                );
            }

            Ok(())
        }
    }
}

const DEFAULT_LOCKBOX_NAME: &str = "lockbox";
fn get_lockbox_filename(name: Option<&str>) -> Result<PathBuf, Error> {
    let filename = format!("{}.protob", name.unwrap_or(DEFAULT_LOCKBOX_NAME));
    home_dir()
        .map(|dir| dir.join("lockbox").join(filename))
        .ok_or(Error::new_invalid_data_error(
            "Error: could not find home directory",
        ))
}
