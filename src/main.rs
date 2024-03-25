#[macro_use]
extern crate rocket;
use rocket::{
    data::ToByteUnit,
    http::Status,
    request::{FromRequest, Outcome},
    response::{status::NotFound, Redirect},
    Data, Request,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sled::{Config, Db};
use std::fs;
use tokio::io::AsyncReadExt;
use toml;

struct ApiKey<'r>(&'r str);

#[derive(Debug, Deserialize)]
struct AppConfig {
    db_path: String,
    api_key: String,
    port: usize,
}

#[derive(Debug)]
enum ApiKeyError {
    Missing,
    Invalid,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey<'r> {
    type Error = ApiKeyError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cf = req
            .rocket()
            .state::<AppConfig>()
            .expect("Failed to retrieve Config from Rocket managed state");

        fn is_valid(key: &str, valid: &str) -> bool {
            key == valid
        }

        match req.headers().get_one("x-api-key") {
            None => Outcome::Error((Status::BadRequest, ApiKeyError::Missing)),
            Some(key) if is_valid(key, &cf.api_key) => Outcome::Success(ApiKey(key)),
            Some(_) => Outcome::Error((Status::BadRequest, ApiKeyError::Invalid)),
        }
    }
}

fn initialize_database(path: &str) -> sled::Result<Db> {
    let db = Config::default().path(path).open()?;
    Ok(db)
}

fn initialize_config() -> Result<AppConfig, toml::de::Error> {
    let text = fs::read_to_string("/etc/fallo/config.toml").expect("Unable to read config file");
    toml::from_str::<AppConfig>(&text)
}

#[delete("/<short>")]
fn delete(
    short: &str,
    key: Result<ApiKey<'_>, ApiKeyError>,
    db: &rocket::State<Db>,
) -> Result<Status, NotFound<String>> {
    if let Err(_e) = key {
        return Ok(Status::Unauthorized);
    }

    if let Ok(_) = db.remove(short) {
        return Ok(Status::Ok);
    }

    Err(NotFound(format!(
        "There is no redirect for the key `{}`",
        short
    )))
}

#[get("/<short>")]
fn redirect(short: &str, db: &rocket::State<Db>) -> Result<Redirect, NotFound<String>> {
    if let Ok(Some(value)) = db.get(short.as_bytes()) {
        if let Ok(value_str) = std::str::from_utf8(&value) {
            return Ok(Redirect::to(value_str.to_string()));
        }
    }
    Err(NotFound(format!(
        "There is no redirect for the key `{}`",
        short
    )))
}

#[post("/<short>", data = "<redir>")]
async fn insert(
    short: &str,
    redir: Data<'_>,
    key: Result<ApiKey<'_>, ApiKeyError>,
    db: &rocket::State<Db>,
) -> Result<(), Status> {
    if let Err(_e) = key {
        return Err(Status::Unauthorized);
    }

    let mut body = String::new();

    if let Err(_e) = redir.open(1.kibibytes()).read_to_string(&mut body).await {
        return Err(Status::BadRequest);
    }

    if let Err(_e) = db.insert(short.as_bytes(), body.trim().as_bytes()) {
        return Err(Status::InternalServerError);
    }

    Ok(())
}

#[get("/")]
async fn list(db: &rocket::State<Db>) -> String {
    let mut json_objects = Map::new();

    for result in db.iter() {
        match result {
            Ok((key, val)) => {
                let key_str = String::from_utf8_lossy(&key).into_owned();
                let val_str = String::from_utf8_lossy(&val).into_owned();

                json_objects.insert(key_str, json!(val_str));
            }
            Err(e) => {
                eprintln!("Error iterating over entries: {:?}", e);
            }
        }
    }

    let json_value = Value::Object(json_objects);

    serde_json::to_string(&json_value).unwrap()
}

#[catch(400)]
fn bad_request() -> String {
    "Invalid URL data".to_string()
}

#[catch(401)]
fn unauthorized() -> String {
    "Invalid or no API key".to_string()
}

#[catch(500)]
fn internal_server_error() -> String {
    "Unable to insert new key into the database :(".to_string()
}

#[launch]
fn rocket() -> _ {
    let cf = initialize_config().expect("Unable to parse config");
    let port = cf.port;

    let db = initialize_database(&cf.db_path).expect("Failed to initialize database");

    rocket::build()
        .manage(db)
        .manage(cf)
        .configure(rocket::Config::figment().merge(("port", port)))
        .register(
            "/",
            catchers![bad_request, unauthorized, internal_server_error],
        )
        .mount("/", routes![delete, insert, list, redirect])
}
