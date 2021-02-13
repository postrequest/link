use std::io::{StdoutLock, Write};

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
    let output = format!(
        "\n\nLink: {}\nTask ID: {}\nCommand: {}\nOutput:\n\n{}\n",
        link_name, task_id, task_command, returned_data,
    );
    let _ = cli_handle.write_all(output.as_bytes()).unwrap();
}
