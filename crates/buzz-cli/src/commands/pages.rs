//! `buzz pages` — Buzz Pages helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag};

use crate::client::BuzzClient;
use crate::error::CliError;

/// Path of the login endpoint on every site host.
const LOGIN_PATH: &str = "/_buzz/login";
/// Separator between repo id and owner prefix in a site label.
const LABEL_SEPARATOR: &str = "--";
/// Hex digits of the owner pubkey carried in a site label.
const OWNER_PREFIX_LEN: usize = 16;

pub async fn dispatch(cmd: crate::PagesCmd, client: &BuzzClient) -> Result<(), CliError> {
    match cmd {
        crate::PagesCmd::Link {
            repo_owner,
            repo_id,
            path,
            host_prefix,
        } => {
            let origin = site_origin(client.relay_url(), &host_prefix, &repo_owner, &repo_id)?;
            let next = format!("/{}", path.trim_start_matches('/'));
            let link = login_link(&origin, client.keys(), &next)?;
            let output = serde_json::json!({
                "url": link,
                "site": format!("{origin}/"),
                "expires_in_seconds": 60,
                "note": "Short-lived login link: open it within 60 seconds. It signs you in as this CLI identity.",
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output)
                    .map_err(|e| CliError::Other(e.to_string()))?
            );
            Ok(())
        }
    }
}

/// Origin of one site: `<scheme>://<repo>--<owner16>.<prefix><relay-host>`.
/// Each site gets its own origin so sites cannot read each other.
fn site_origin(
    relay_url: &str,
    host_prefix: &str,
    repo_owner: &str,
    repo_id: &str,
) -> Result<String, CliError> {
    let owner_ok = repo_owner.len() == 64
        && repo_owner
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    if !owner_ok {
        return Err(CliError::Usage(
            "--repo-owner must be a 64-character lowercase hex pubkey".into(),
        ));
    }
    let repo_ok = !repo_id.is_empty()
        && repo_id.len() <= 45
        && !repo_id.starts_with('-')
        && !repo_id.ends_with('-')
        && repo_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !repo_ok {
        return Err(CliError::Usage(format!(
            "repo id {repo_id:?} cannot be a Buzz Pages site: use lowercase letters, digits and '-' (max 45)"
        )));
    }
    let (scheme, rest) = relay_url
        .split_once("://")
        .ok_or_else(|| CliError::Usage(format!("relay URL has no scheme: {relay_url}")))?;
    let scheme = match scheme {
        "wss" | "https" => "https",
        _ => "http",
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let prefix = if host_prefix.ends_with('.') {
        host_prefix.to_string()
    } else {
        format!("{host_prefix}.")
    };
    Ok(format!(
        "{scheme}://{repo_id}{LABEL_SEPARATOR}{}.{prefix}{authority}",
        &repo_owner[..OWNER_PREFIX_LEN]
    ))
}

/// Build a site login URL carrying a NIP-98 event signed for the site's
/// login endpoint. The relay exchanges it for a session cookie and redirects
/// to `next`.
fn login_link(origin: &str, keys: &Keys, next: &str) -> Result<String, CliError> {
    let login_url = format!("{origin}{LOGIN_PATH}");
    let tags = [
        Tag::parse(["u", login_url.as_str()]),
        Tag::parse(["method", "GET"]),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| CliError::Other(format!("tag error: {e}")))?;
    let event = EventBuilder::new(Kind::Custom(27235), "")
        .tags(tags)
        .sign_with_keys(keys)
        .map_err(|e| CliError::Other(format!("NIP-98 signing failed: {e}")))?;
    let token = URL_SAFE_NO_PAD.encode(event.as_json());
    let next = url::form_urlencoded::byte_serialize(next.as_bytes()).collect::<String>();
    Ok(format!("{login_url}?token={token}&next={next}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "fabe1ffc0a550dcb33a083cb36a120d975a429ce518e32508dda6a075b4c4e18";

    #[test]
    fn site_origin_is_per_repo() {
        assert_eq!(
            site_origin("https://buzz.example", "apps", OWNER, "team-dash").expect("origin"),
            "https://team-dash--fabe1ffc0a550dcb.apps.buzz.example"
        );
        assert_eq!(
            site_origin("ws://localhost:3000", "apps.", OWNER, "x").expect("origin"),
            "http://x--fabe1ffc0a550dcb.apps.localhost:3000"
        );
        for bad_repo in ["Team", "team_dash", "-x", "x-", "a.b", ""] {
            assert!(site_origin("https://b.example", "apps.", OWNER, bad_repo).is_err());
        }
        assert!(site_origin("https://b.example", "apps.", "ABC", "x").is_err());
    }

    #[test]
    fn link_signs_the_site_login_url() {
        let keys = Keys::generate();
        let origin = "https://x--fabe1ffc0a550dcb.apps.buzz.example";
        let link = login_link(origin, &keys, "/docs/").expect("link builds");
        let (base, query) = link.split_once('?').expect("has query");
        assert_eq!(base, format!("{origin}/_buzz/login"));

        let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(params[1], ("next".into(), "/docs/".into()));
        let json = URL_SAFE_NO_PAD.decode(&params[0].1).expect("base64url");
        let event = nostr::Event::from_json(json).expect("event json");
        assert_eq!(event.kind, Kind::Custom(27235));
        assert_eq!(event.pubkey, keys.public_key());
        let u = event
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("u"))
            .and_then(|t| t.as_slice().get(1).cloned());
        assert_eq!(u.as_deref(), Some(base));
    }
}
