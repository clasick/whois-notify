extern crate filecmp;
extern crate fern;
extern crate regex;
extern crate whois_rust;

use std::fs;
use std::path::Path;
use std::process;

use chrono;
use log::{error, info};
use whois_rust::{WhoIs, WhoIsLookupOptions};

fn setup_logger() -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Debug)
        // .chain(std::io::stdout())
        .chain(fern::log_file("log.txt")?)
        .apply()?;
    Ok(())
}

// defining constants
const RESULT_FILE: &str = "./result.txt";
const OLD_RESULT_FILE: &str = "./old-result.txt";
const SERVER_FILE: &str = "./src/servers.json";
const DOMAIN_ADDRESS: &str = "vignesh.co";

fn quit_error(_e: std::io::Error) {
    process::exit(-1);
}

fn main() -> std::io::Result<()> {
    setup_logger().expect("Couldn't setup logging");

    let whois = WhoIs::from_path(SERVER_FILE).unwrap();

    let mut result: String = whois
        .lookup(WhoIsLookupOptions::from_string(DOMAIN_ADDRESS).unwrap())
        .unwrap();

    let re = regex::Regex::new(r"\d*-\d*-\d*.*Z").unwrap();
    result = re.replace_all(&result, "").to_string();

    match Path::new(RESULT_FILE).exists() {
        true => {
            match Path::new(OLD_RESULT_FILE).exists() {
                true => fs::remove_file(OLD_RESULT_FILE)
                    .expect("Couldn't remove existing old result file!"),
                false => {}
            }
            fs::rename(RESULT_FILE, OLD_RESULT_FILE).expect("Couldn't rename existing file!");
        }
        false => {}
    };

    match fs::write(RESULT_FILE, result) {
        Ok(_) => info!("Wrote into result.txt file."),
        Err(e) => {
            error!("Couldn't write into file!");
            quit_error(e);
        }
    }

    match filecmp::cmp(RESULT_FILE, OLD_RESULT_FILE, false) {
        Ok(true) => info!("WHOIS is the same."),
        Ok(false) => info!("WHOIS has changed!"),
        Err(_) => error!("Error while comparing files."),
    }

    Ok(())
}
