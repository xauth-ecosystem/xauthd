use axum::response::Html;

use super::state::AppState;

pub fn render_template(
    templates_dir: &str,
    name: &str,
    ctx: minijinja::Value,
) -> Result<Html<String>, String> {
    let mut env = minijinja::Environment::new();
    env.set_loader(minijinja::path_loader(templates_dir));
    let tmpl = env.get_template(name).map_err(|e| e.to_string())?;
    let rendered = tmpl.render(ctx).map_err(|e| e.to_string())?;
    Ok(Html(rendered))
}

pub fn get_username_from_cookie(headers: &axum::http::HeaderMap, state: &AppState) -> String {
    if let Some(cookie_val) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_val.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(token) = part.strip_prefix("session_token=") {
                    if let Ok(claims) =
                        crate::services::jwt::validate_jwt(token, &state.settings.jwt.secret)
                    {
                        return claims.sub;
                    }
                }
            }
        }
    }
    "Guest".to_string()
}
