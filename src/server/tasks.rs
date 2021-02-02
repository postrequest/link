use std::io::{StdoutLock, Write};

#[derive(Debug, Default)]
pub struct Tasks {
    pub tasks:  Vec<Task>,
}

#[derive(Debug)]
pub struct Task {
    pub id:         uuid::Uuid,
    pub command:    String,
    pub status:     TaskStatus,
    pub output:     String,
}

#[derive(Debug, PartialEq)]
pub enum TaskStatus {
    Waiting,
    InProgress,
    Completed,
}

// command help struct
pub struct Command {
    pub name:   String,
    pub help:   String,
}

// print new link to stdout
pub fn write_link_to_stdout(cli_handle: &mut StdoutLock, link_name: String) {
	let output = format!("\n\n🔗 New link: {} 🔗\n",
	    link_name,
	);
	let _ = cli_handle.write_all(output.as_bytes()).unwrap();
}

// print returned task output to stdout
pub fn write_task_to_stdout(cli_handle: &mut StdoutLock, link_name: String, task_id: String, task_command: String, returned_data: &str) {
	let output = format!("\n\nLink: {}\nTask ID: {}\nCommand: {}\nOutput:\n\n{}\n",
        link_name,
        task_id,
        task_command,
        returned_data,
	);
	let _ = cli_handle.write_all(output.as_bytes()).unwrap();
}

// execute .NET assembly remotely in memory
pub fn execute_assembly() {
    /*
dumpbin /exports Z:\HostingCLRx64.dll
Microsoft (R) COFF/PE Dumper Version 14.27.29112.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file Z:\HostingCLRx64.dll

File Type: DLL

  Section contains the following exports for HostingCLRx64.dll

    00000000 characteristics
    5ED757D9 time date stamp Wed Jun  3 00:57:13 2020
        0.00 version
           1 ordinal base
           1 number of functions
           1 number of names

    ordinal hint RVA      name

          1    0 00001CB0 ?ReflectiveLoader@@YA_KPEAX@Z

  Summary

        2000 .data
        1000 .gfids
        2000 .pdata
        B000 .rdata
        1000 .reloc
        1000 .rsrc
       15000 .text

C:\Program Files (x86)\Microsoft Visual Studio\2019\Community>

	*/
}

