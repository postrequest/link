// internal packages
pub mod routes;
pub mod server;
pub mod util;

#[actix_web::main]
async fn main() {
    util::cli::main_loop().await;
}
