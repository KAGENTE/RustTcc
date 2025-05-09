#[macro_use] extern crate rocket;

use std::env;
use rocket::form::Form;
use rocket::fs::{relative, FileServer};
use rocket::http::Cookie;
use rocket::http::private::cookie::CookieJar;
use rocket::response::Redirect;
use rocket::serde::{Deserialize, Serialize};
use rocket_dyn_templates::{Template, context};
use argon2::{self, password_hash::{SaltString, PasswordHasher, PasswordVerifier, rand_core::OsRng, PasswordHash}};
use argon2::Argon2;
use dotenvy::dotenv;
use rocket::State;
use sqlx::PgPool;

#[derive(FromForm)]
struct LoginForm{
    email: String,
    password: String,
}

#[derive(sqlx::FromRow)]
struct User {
    id: i32,
    name: String,
    email: String,
    password: String,
}



pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
}


#[get("/")]
fn root() -> Redirect {
    Redirect::to(uri!(home))
}

#[get("/home")]
fn home() -> Template {
    Template::render("home", context! {
        page_title: "Mel00n - Home",
    })
}

#[get("/login")]
fn login() -> Template {
    Template::render("login",context! {
        page_title: "Mel00n - Login",})
}


#[post("/login", data = "<login_form>")]
async fn log_in(
    cookies: &CookieJar,
    login_form: Form<LoginForm>,
    db: &State<PgPool>,
) -> Redirect {
    let form = login_form.into_inner();

    let result = sqlx::query_as!(
        User,
        "SELECT id, name, email, password FROM users WHERE email = $1",
        form.email
    )
        .fetch_optional(db.inner())
        .await;

    match result {
        Ok(Some(user)) => {
            match verify_password(&form.password, &user.password) {
                Ok(true) => {
                    cookies.add_private(Cookie::new("user_email", user.email));
                    cookies.add_private(Cookie::new("user_name", user.name));
                    Redirect::to(uri!(home))
                }
                _ => Redirect::to(uri!(login)),
            }
        }
        _ => Redirect::to(uri!(login)),
    }
}


#[get("/ingredients")]
fn ingredients(cookies: &CookieJar) -> Template {
    let user_name = cookies.get_private("user_name").map(|c| c.value().to_string());

    Template::render("ingredients", context! {
        page_title: "Mel00n - Ingredients",
        user: user_name
    })
}


#[get("/favs")]
fn favs() -> Template {
    Template::render("favs", context! {
        page_title: "Mel00n - Favs",
    })
}


#[launch]
fn rocket() -> _ {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let db_pool = PgPool::connect_lazy(&database_url)
        .expect("Failed to create pool");

    rocket::build()
        .manage(db_pool)
        .mount("/", routes![root, home, login, log_in, ingredients, favs])
        .mount("/", FileServer::from(relative!("static")))
        .attach(Template::fairing())
}
