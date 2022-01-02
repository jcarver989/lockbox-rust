use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "lockbox", about = "A CLI for password management")]
pub enum Opt {
    New(NewCommand),
    Add(AddCommand),
    Edit(EditCommand),
    List(ListCommand),
    Decrypt(FindByIdCommand),
    ImportLastPass(ImportLastPassCommand),
}

#[derive(Debug, StructOpt)]
pub struct NewCommand {
    #[structopt(short = "n", long = "name")]
    pub name: Option<String>,

    #[structopt(short = "m", long = "master-password")]
    pub master_password: String,
}

#[derive(Debug, StructOpt)]
pub struct AddCommand {
    #[structopt(short = "n", long = "name")]
    pub name: Option<String>,

    #[structopt(short = "m", long = "master-password")]
    pub master_password: String,

    #[structopt(short = "u", long = "username")]
    pub username: String,

    #[structopt(long = "url")]
    pub url: String,

    #[structopt(short = "p", long = "password")]
    pub password: String,

    #[structopt(short = "d", long = "notes")]
    pub notes: Option<String>,
}

#[derive(Debug, StructOpt)]
pub struct EditCommand {
    #[structopt(short = "n", long = "name")]
    pub name: Option<String>,

    #[structopt(short = "m", long = "master-password")]
    pub master_password: String,

    #[structopt(long = "id")]
    pub id: String,

    #[structopt(short = "u", long = "username")]
    pub username: Option<String>,

    #[structopt(long = "url")]
    pub url: Option<String>,

    #[structopt(short = "p", long = "password")]
    pub password: Option<String>,

    #[structopt(short = "d", long = "notes")]
    pub notes: Option<String>,
}

#[derive(Debug, StructOpt)]
pub struct ListCommand {
    #[structopt(short = "m", long = "master-password")]
    pub master_password: String,

    #[structopt(short = "n", long = "name")]
    pub name: Option<String>,
}

#[derive(Debug, StructOpt)]
pub struct FindByIdCommand {
    #[structopt(short = "n", long = "name")]
    pub name: Option<String>,

    #[structopt(short = "m", long = "master-password")]
    pub master_password: String,

    #[structopt(short = "i", long = "id")]
    pub id: String,
}

#[derive(Debug, StructOpt)]
pub struct ImportLastPassCommand {
    #[structopt(short = "n", long = "name")]
    pub name: Option<String>,

    #[structopt(short = "m", long = "master-password")]
    pub master_password: String,

    #[structopt(short = "f", long = "file")]
    pub file: PathBuf,
}
