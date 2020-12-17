extern crate fern;
extern crate filecmp;
extern crate job_scheduler;
extern crate notify_rust;
extern crate regex;
extern crate whois_rust;

use std::fs;
use std::path::Path;
use std::process;
use std::time::Duration;

use chrono;
use job_scheduler::{Job, JobScheduler};
use log::{error, info};
use notify_rust::Notification;
use whois_rust::{WhoIs, WhoIsLookupOptions};

// set up logging
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
        .chain(std::io::stdout())
        .chain(fern::log_file("log.txt")?)
        .apply()?;
    Ok(())
}

// defining constants
const RESULT_FILE: &str = "./result.txt";
const OLD_RESULT_FILE: &str = "./old-result.txt";
const SERVER_FILE: &str = "./src/servers.json";
const DOMAIN_ADDRESS: &str = "vignesh.co";

fn quit_error(error: std::io::Error) {
    error!("{}", error);
    process::exit(-1);
}

fn requirements() -> bool {
    match Path::new(SERVER_FILE).exists() {
        true => return true,
        false => {
            error!("Could't find server file at {}", SERVER_FILE);
            return false;
        }
    }
}

fn who_is() -> std::io::Result<()> {
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
        Ok(_) => {}
        Err(e) => {
            error!("Couldn't write into file!");
            quit_error(e);
        }
    }

    match filecmp::cmp(RESULT_FILE, OLD_RESULT_FILE, false) {
        Ok(true) => info!("WHOIS is the same."),
        Ok(false) => {
            info!("WHOIS has changed!");

            Notification::new()
                .summary("WHOIS Track")
                .body("Found a WHOIS change for the domain!")
                .show()
                .unwrap();
        }
        Err(_) => error!("Error while comparing files."),
    }

    Ok(())
}

fn main() {
    setup_logger().expect("Couldn't set up logging.");

    match requirements() {
        true => {}
        false => {
            quit_error(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Couldn't find the required files.",
            ));
        }
    }

    let mut sched = JobScheduler::new();

    sched.add(Job::new("0 * * * * *".parse().unwrap(), || {
        info!("Looking up WHOIS info...");
        who_is().expect("Couldn't check WHOIS");
    }));

    loop {
        sched.tick();

        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_notifications() {
        Notification::new()
            .summary("Test notification")
            .body("Test notification")
            .show()
            .unwrap();
    }
}
