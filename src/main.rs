// internal packages
pub mod util;
pub mod server;
pub mod routes;

#[actix_web::main]
async fn main() {
    util::cli::main_loop().await;
}

