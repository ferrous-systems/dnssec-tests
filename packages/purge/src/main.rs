use std::{
    error::Error,
    io::{self, Write},
    process::{exit, Command, Output},
};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        exit(1)
    }
}

fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();

    let mut clean_network = false;
    let mut clean_container = false;

    match args.first().map(String::as_str) {
        Some("network") => {
            clean_network = true;
        }
        Some("container") => {
            clean_container = true;
        }
        None => {
            clean_network = true;
            clean_container = true;
        }
        Some(unexpected) => {
            return Err(io_error(format!("Unexpected argument `{unexpected}`")));
        }
    }

    if clean_container {
        let hashes = filter_command_output(Command::new("docker").arg("ps"))?;

        if hashes.is_empty() {
            println!("No containers to be removed");
        } else {
            let output = run_command(Command::new("docker").args(["rm", "-f"]).args(hashes))?;

            println!("Removed containers:");
            io::stdout().write_all(&output.stdout)?;
        }
    }

    if clean_network {
        let hashes = filter_command_output(Command::new("docker").args(["network", "ls"]))?;

        if hashes.is_empty() {
            println!("No networks to be removed");
        } else {
            let output = run_command(Command::new("docker").args(["network", "rm"]).args(hashes))?;

            println!("Removed networks:");
            io::stdout().write_all(&output.stdout)?;
        }
    }

    Ok(())
}

fn run_command(command: &mut Command) -> io::Result<Output> {
    let output = command.output()?;

    if !output.status.success() {
        return Err(io_error(format!(
            "command {:?} exited with status-code {:?}, stderr:\n{}",
            command.get_program(),
            output.status,
            String::from_utf8_lossy(&output.stderr),
        )));
    }

    Ok(output)
}

fn filter_command_output(command: &mut Command) -> io::Result<Vec<String>> {
    String::from_utf8(run_command(command)?.stdout)
        .map_err(io_error)
        .map(|stdout| {
            stdout
                .lines()
                .filter(|&line| line.contains("dns-test"))
                .map(|line| line[..12].to_owned())
                .collect()
        })
}

fn io_error(msg: impl Into<Box<dyn Error + Sync + Send + 'static>>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}
