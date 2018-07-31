// options {{{
#![allow(unused_must_use)]
extern crate clap;
extern crate csv;
extern crate dotenv;
#[macro_use]
extern crate duct;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate dotenv_codegen;
// use duct::cmd;
use clap::{App, Arg, SubCommand};
use dotenv::dotenv;
use std::env;
use std::error::Error;
use std::fs::File;
use std::process;

#[derive(Debug, Deserialize)]
struct Record {
    alias: String,
    ip: String,
    user: String,
    pass: String,
    func: String,
}
// }}}
// read file {{{
fn read(login: &mut Vec<((String, String, String, String, String))>) -> Result<(), Box<Error>> {
    let file = File::open("list")?;
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(file);
    for result in rdr.deserialize() {
        let record: Record = result?;
        login.push((
            record.alias,
            record.ip,
            record.user,
            record.pass,
            record.func,
        ))
    }
    Ok(())
}
// }}}
fn main() {
    // init .env file
    dotenv().ok();
    // init vecs
    let mut login = vec![];
    // read csv {{{
    if let Err(err) = read(&mut login) {
        println!("error running example: {}", err);
        process::exit(1);
    }
    // println!("{:?}", login);
    // }}}
    // initialize clap {{{
    let matches = App::new("ice")
        .version("1.0")
        .author("ice")
        .about("cli")
        .arg(Arg::with_name("input").help("function to exec").index(1))
        .subcommand(
            SubCommand::with_name("p")
                .about("backlan ping")
                .arg(Arg::with_name("ip").help("ip to ping on backlan").index(1)),
        )
        .subcommand(
            SubCommand::with_name("n")
                .about("backlan nmap")
                .arg(Arg::with_name("ip").help("ip to nmap on backlan").index(1)),
        )
        .get_matches();
    // Backlan Subcommand:
    if let Some(matches) = matches.subcommand_matches("p") {
        if let Some(i) = matches.value_of("ip") {
            backlanping(i.to_string())
        }
    }
    if let Some(matches) = matches.subcommand_matches("n") {
        if let Some(i) = matches.value_of("ip") {
            backlannmap(i.to_string())
        }
    }
    // }}}
    // Main Commands: {{{
    if let Some(o) = matches.value_of("input") {
        println!("INPUT: {}", o);
        match o {
            "b" => build(),
            _ => {
                // file function finder:
                // iterate login, filter for element where i.0 == o(input args)
                let t = login.into_iter().filter(|i| i.0 == o).collect::<Vec<_>>();
                // get vars from first match
                let ip = t[0].1.to_string();
                let mut user = t[0].2.to_string();
                let mut pass = t[0].3.to_string();
                let func = t[0].4.to_string();
                // match user with environment variable
                match user.as_ref() {
                    "RR" => user = env::var("RR").expect("RR not found"),
                    "RI" => user = env::var("RI").expect("RI not found"),
                    "RP" => user = env::var("RP").expect("RP not found"),
                    "RA" => user = env::var("RA").expect("RA not found"),
                    "RS" => user = env::var("RS").expect("RS not found"),
                    "RL" => user = env::var("RL").expect("RL not found"),
                    "RM" => user = env::var("RM").expect("RM not found"),
                    _ => (),
                }
                // match pass with environment variable
                match pass.as_ref() {
                    "SG" => pass = env::var("SG").expect("SG not found"),
                    "S5" => pass = env::var("S5").expect("S5 not found"),
                    "SU" => pass = env::var("SU").expect("SU not found"),
                    "SV" => pass = env::var("SV").expect("SV not found"),
                    "SX" => pass = env::var("SX").expect("SX not found"),
                    "SM" => pass = env::var("SM").expect("SM not found"),
                    "SD" => pass = env::var("SD").expect("SD not found"),
                    "SW" => pass = env::var("SW").expect("SW not found"),
                    "SP" => pass = env::var("SP").expect("SP not found"),
                    "SC" => pass = env::var("SC").expect("SC not found"),
                    "SZ" => pass = env::var("SZ").expect("SZ not found"),
                    _ => (),
                }
                // match function
                match func.as_ref() {
                    "ssh" => ssh(ip, user, pass),
                    "sso" => sso(ip, user),
                    "rd" => rd(ip, user, pass),
                    _ => (),
                }
            }
        }
    }
    // }}}
}
// ssh {{{
fn ssh(ip: String, user: String, pass: String) {
    // requires #![allow(unused_must_use)] to not return error with .unwrap()
    // string composition
    let blan = String::from("expect -c 'spawn ssh pspinc@216.230.243.243;expect \"pspinc\"");
    let lan = format!("expect -c 'spawn ssh {}@{};expect \"password\";send \"{}\n\";expect \"{}\"", user, ip, pass, user);
    let ssh = format!(
        ";send \"ssh {}@{}\n\";expect \"password\";send \"{}\n\";expect \"{}\"",
        user, ip, pass, user
    );
    let root = format!(
        ";send \"sudo su -\n\";expect \"password\";send \"{}\n\";expect \"root\"",
        pass
    );
    let interact = String::from(";interact'");
    let slice = &ip[0..2];
    match slice.as_ref() {
        // handle blan {{{
        "10" => match user.as_ref() {
            "pspinc" | "psp" => {
                let command = format!("{}{}{}{}", blan, ssh, root, interact);
                cmd!("bash", "-c", command).run();
            }
            "root" => {
                let command = format!("{}{}{}", blan, ssh, interact);
                cmd!("bash", "-c", command).run();
            }
            _ => println!("Cannot handle user"),
        },
        // }}}
        // handle lan {{{
        _ => match user.as_ref() {
            "pspinc" | "psp" => {
                let command = format!(
        "{}{}{}",
        lan, root, interact
    );
                cmd!("bash", "-c", command).run();
            }
            "root" => {
                let command = format!(
        "{}{}",
        lan, interact
    );
                cmd!("bash", "-c", command).run();
            }
            _ => (),
        },
        // }}}
    }
}
// }}}
// sso {{{
fn sso(ip: String, user: String) {
    let blan = format!("expect -c 'spawn ssh pspinc@216.230.243.243;expect \"pspinc\";send \"ssh {}@{}\n\"", user, ip);
    let lan = format!("expect -c 'spawn ssh {}@{}", user, ip);
    let interact = String::from(";interact'");
    let slice = &ip[0..2];
    match slice.as_ref() {
        "10" => match user.as_ref() {
            "pspinc" | "psp" => {
                let command = format!(
                "{}{}", blan, interact);
                cmd!("bash", "-c", command).run();
            }
            "root" => {
                let command = format!("{}{}", blan, interact);
                cmd!("bash", "-c", command).run();
            }
            _ => println!("Cannot handle user"),
        },
        _ => match user.as_ref() {
            "pspinc" | "psp" => {
                let command = format!("{}{}", lan, interact);
                cmd!("bash", "-c", command).run();
            }
            "root" => {
                let command = format!("{}{}", lan, interact);
                cmd!("bash", "-c", command).run();
            }
            _ => (),
        },
    }
}
// }}}
// rdesktop {{{
fn rd(ip: String, user: String, pass: String) {
    let slice = &ip[0..2];
    // println!("{}", slice);
    match slice.as_ref() {
        "10" => {
            let command = format!(
                "ssh -f -N -D9050 pspinc@216.230.243.243; proxychains rdesktop -g 1300x708 -u {} -p '{}' {}",
                // "ssh -f -N -D9050 pspinc@216.230.243.243; proxychains rdesktop -g 1300x708 -5 -K -r disk:sharename=/home/fish/Documents/sync -u {} -p '{}' {}",
                user, pass, ip
            );
            // println!("{}", command);
            cmd!("sh", "-c", command).run();
        }
        _ => {
            let command = format!(
                "rdesktop -g 1300x708 -u {} -p '{}' {}",
                // "rdesktop -g 1300x708 -5 -K -r clipboard:CLIPBOARD -u {} -p '{}' {}",
                user, pass, ip
            );
            // println!("{}", command);
            cmd!("sh", "-c", command).run();
        }
    }
}
// }}}
// tools {{{
fn build() {
    let cmd = format!("cd {}/m/file;cargo build", dotenv!("HOME"));
    cmd!("bash", "-c", cmd).run().unwrap();
}

fn backlanping(ip: String) {
    // println!("hi")
    let cmd = format!("ssh -t pspinc@216.230.243.243 ping {}", ip);
    // println!("{}{}", cmd, ip);
    cmd!("bash", "-c", cmd).run().unwrap();
}
fn backlannmap(ip: String) {
    // println!("hi")
    let cmd = format!("ssh -t pspinc@216.230.243.243 nmap {}", ip);
    // println!("{}{}", cmd, ip);
    cmd!("bash", "-c", cmd).run().unwrap();
}
// }}}
// notes
// let mut v = vec![1, 2, 3];
// v.clear();
// assert!(v.is_empty());
