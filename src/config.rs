use getopts::Options;
use rustc_serialize::Decodable;
use std::env;
use std::fs::File;
use std::path::Path;
use std::error::Error;
use std::{io, process, convert};
use std::io::Read;
use toml;

#[derive(Debug, RustcDecodable)]
pub struct CertChainConfig {
    pub listener_port: u16,
    pub rpc_port: u16,
    pub peers: Vec<CertChainConfigPeer>,
    pub secret_key: String,
    pub compressed_public_key: String,
}

#[derive(Debug, RustcDecodable)]
pub struct CertChainConfigPeer {
    pub name: String,
    pub hostname: String,
    pub port: u16,
}

#[derive(Debug)]
pub enum ConfigLoadError {
    EmptyError,
    LoadIoError(io::Error),
    ParseError(toml::ParserError),
    DecodeError(toml::DecodeError),
}

impl convert::From<io::Error> for ConfigLoadError {
    fn from(err: io::Error) -> ConfigLoadError {
        ConfigLoadError::LoadIoError(err)
    }
}

impl convert::From<toml::DecodeError> for ConfigLoadError {
    fn from(err: toml::DecodeError) -> ConfigLoadError {
        ConfigLoadError::DecodeError(err)
    }
}

pub fn load() -> Result<CertChainConfig, ConfigLoadError> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("c", "config", "set config file path", "CONFIG");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m },
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        process::exit(0);
    }

    // Get path to config file and open file for reading.
    let config_file_path_str = match matches.opt_str("c") {
        Some(c) => { c },
        None => { panic!("You must provide a config file path; use -c or --config.") }
    };
    let config_file_path = Path::new(&config_file_path_str);
    let mut config_file = match File::open(&config_file_path) {
        Err(why) => panic!("Unable to open config file {}: {}",
                                config_file_path.display(), Error::description(&why)),
        Ok(file) => file
    };

    // Read file contents into string.
    let mut config_file_text = String::new();
    config_file.read_to_string(&mut config_file_text).unwrap();

    // Parse the TOML from the file's string representation.
    let mut parser = toml::Parser::new(&config_file_text[..]);
    let toml_table = match parser.parse() {
        Some(table) => toml::Value::Table(table),
        None => return Err(ConfigLoadError::ParseError(
                                parser.errors.pop().unwrap())),
    };

    // Deserialize the TOML table into a respective struct instance.
    let mut decoder = toml::Decoder::new(toml_table);
    let config : CertChainConfig = try!(CertChainConfig::decode(&mut decoder));
    Ok(config)
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}
