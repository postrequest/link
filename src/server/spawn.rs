use actix_web::{dev::Server, web, App, HttpServer};
use std::{
    path::Path,
    process::exit,
    sync::{mpsc, Mutex},
    thread,
};

// internal packages
use crate::routes;
use crate::server;
use crate::util;
use server::links::Links;
use util::cli::cli_line;

pub async fn spawn_server(
    tx: &mpsc::Sender<Server>,
    rx_command: &mpsc::Receiver<std::io::Stdout>,
    bind_addr: String,
) -> web::Data<Links> {
    //std::env::set_var("RUST_LOG", "link");
    //env_logger::init();
    let tx = tx.to_owned();
    let rx_command = rx_command.to_owned();
    let links_init = web::Data::new(Links {
        links: Mutex::new(Vec::new()),
        count: Mutex::new(0),
        stdout: Mutex::new(rx_command.recv().unwrap()),
    });
    let links = links_init.clone();
    // check certificate path
    let (key_path, cert_path) = if Path::new("cert").exists() { 
        check_certs("cert".to_string())
    } else {
        let arg = cli_line("Please provide full path to folder with certificates (contains key.pem and cert.pem): ");
        if Path::new(&arg[0]).exists() {
            check_certs(arg[0].clone())
        } else { 
            exit(1);
        }
    };
    
    thread::spawn(move || {
        // load links
        // load ssl
        // openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'
        let mut builder =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .unwrap();
        builder
            .set_private_key_file(&key_path, openssl::ssl::SslFiletype::PEM)
            .unwrap();
        builder.set_certificate_chain_file(&cert_path).unwrap();
        // web server
        let sys = actix_web::rt::System::new("protocol-web-server");
        let pre_srv = HttpServer::new(move || {
            App::new()
                // logging
                //.wrap(actix_web::middleware::Logger::default())
                // links
                .app_data(links.clone())
                // payload delivery that is linked with xeca
                //.service(web::scope("/css").configure(payload_delivery))
                // first round of proving the link
                .service(web::scope("/js").configure(routes::urls::stage_one_pass))
                // provides access to link functions
                .service(web::scope("/static").configure(routes::urls::pass_link_config))
                // non link traffic
                .service(routes::urls::index)
        })
        .shutdown_timeout(1)
        .bind_openssl(bind_addr.as_str(), builder);
        if pre_srv.is_err() {
            println!(
                "Could not bind to {}: {}",
                bind_addr,
                pre_srv.err().unwrap()
            );
            std::process::exit(1);
        }
        let srv = pre_srv?.run();

        let _ = tx.send(srv);
        sys.run()
    });
    links_init
}

fn check_certs(cert_dir: String) -> (String, String) { 
    // check for key.pem and cert.pem
    let key_path = format!("{}/key.pem", &cert_dir);
    let cert_path = format!("{}/cert.pem", &cert_dir);
    if !Path::new(&key_path).exists() || !Path::new(&cert_path).exists() {
        println!("Certificate directory \"{}\" does not contain key.pem or cert.pem", &cert_dir);
        exit(1);
    }
    (key_path, cert_path)
}
