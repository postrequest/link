// this will hold links in memory
// log and save to database in the future
extern crate chrono;
extern crate uuid;
use chrono::prelude::*;
use std::sync::Mutex;

// internal packages
use crate::server;
use server::{tasks, tasks::TaskStatus};

#[derive(Debug)]
pub struct Links {
    pub links: Mutex<Vec<Link>>,
    pub count: Mutex<i32>,
    pub stdout: Mutex<std::io::Stdout>,
}

#[derive(Debug)]
pub struct Link {
    pub status: LinkStatus,
    pub name: String,
    pub x_request_id: uuid::Uuid,
    pub link_type: LinkType,
    pub platform: String,
    pub architecture: String,
    pub link_username: String,
    pub link_hostname: String,
    pub internal_ip: String,
    pub external_ip: String,
    pub delay: u32,
    pub jitter: u32,
    pub pid: u32,
    pub process_name: String,
    pub first_checkin: DateTime<Local>,
    pub last_checkin: DateTime<Local>,
    pub protocol: String,
    pub user_agent: String,
    pub tasks: tasks::Tasks,
}

impl Link {
    pub fn new() -> Link {
        let init_uuid = uuid::Uuid::new_v4();
        let link_name: String = uuid::Uuid::new_v4()
            .to_string()
            .split("-")
            .map(str::to_string)
            .collect();
        Link {
            status: LinkStatus::Initializing,
            name: link_name,
            x_request_id: init_uuid,
            // this implementation will need to change once KM link is working
            link_type: LinkType::Ring3,
            platform: "windows".to_string(),
            architecture: "x86_64".to_string(),
            link_username: "".to_string(),
            link_hostname: "".to_string(),
            internal_ip: "".to_string(),
            external_ip: "".to_string(),
            delay: 0,
            jitter: 0,
            pid: 0,
            process_name: "".to_string(),
            first_checkin: Local::now(),
            last_checkin: Local::now(),
            protocol: "HTTP2".to_string(),
            user_agent: "".to_string(),
            tasks: tasks::Tasks::default(),
        }
    }

    pub fn update_last_checkin(&mut self) {
        self.last_checkin = Local::now();
    }

    pub fn check_status(&mut self) {
        let now = Local::now().timestamp();
        let most_recent = self.last_checkin.timestamp();
        let diff = now - most_recent;
        if diff > 90 {
            self.status = LinkStatus::Inactive;
        }
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn set_x_request_id(&mut self) -> String {
        let new_uuid = uuid::Uuid::new_v4();
        self.x_request_id = new_uuid;
        new_uuid.to_string()
    }

    pub fn set_command(&mut self, command_to_execute: String, raw_command: String) {
        let task = tasks::Task {
            id: uuid::Uuid::new_v4(),
            command: command_to_execute,
            cli_command: raw_command,
            status: TaskStatus::Waiting,
            output: "".to_string(),
        };
        self.tasks.tasks.push(task);
    }

    pub fn update_task_status(&mut self, status: TaskStatus, id: String) {
        // find task id
        let task_count = self.tasks.tasks.len();
        let task_index: usize;
        for i in 0..task_count {
            if self.tasks.tasks[i as usize].id.to_string() == id {
                task_index = i;
                // if task is to kill link, set link status to inactive
                if self.tasks.tasks[task_index].command.as_str() == "exit" {
                    match status {
                        TaskStatus::Waiting => {
                            self.tasks.tasks[task_index].status = TaskStatus::Waiting
                        }
                        TaskStatus::InProgress => {
                            self.tasks.tasks[task_index].status = TaskStatus::Completed;
                            self.status = LinkStatus::Exited;
                            self.remove_task(task_index);
                            // TODO
                            // send link kill to stdout
                            break;
                        }
                        // TODO
                        // log output file
                        // remote task from memory
                        TaskStatus::Completed => self.remove_task(task_index),
                    }
                }
                // match and update
                match status {
                    TaskStatus::Waiting => {
                        self.tasks.tasks[task_index].status = TaskStatus::Waiting
                    }
                    TaskStatus::InProgress => {
                        self.tasks.tasks[task_index].status = TaskStatus::InProgress
                    }
                    // TODO
                    // log output file
                    // remote task from memory
                    TaskStatus::Completed => self.remove_task(task_index),
                }
                break;
            }
        }
    }

    // Add logging functionality to file
    pub fn remove_task(&mut self, task_id: usize) {
        self.tasks.tasks.remove(task_id);
    }
}

#[derive(Debug, PartialEq)]
pub enum LinkStatus {
    Initializing,
    Staging,
    Active,
    Inactive,
    Exited,
}

#[derive(Debug, PartialEq)]
pub enum IntegrityLevel {
    Low,
    Medium,
    High,
    System,
}

#[derive(Debug, PartialEq)]
pub enum LinkType {
    Ring3,
    Ring0,
}
