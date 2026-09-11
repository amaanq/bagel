use std::{
   collections::BTreeMap,
   sync::LazyLock,
   time::Duration,
};

use http::{
   Request,
   Uri,
   header,
   uri::Authority,
};
use http_body_util::{
   BodyExt as _,
   Limited,
};
use hyper_util::client::legacy::{
   Client,
   connect::HttpConnector,
};
use regex::Regex;

use crate::{
   body::Body,
   net::decay_map::DecayMap,
};

static TAG_RE: LazyLock<Regex> =
   LazyLock::new(|| Regex::new(r"(?i)<(meta|link)\s([^>]*)/??>").unwrap());
static ATTR_RE: LazyLock<Regex> =
   LazyLock::new(|| Regex::new(r#"(?i)(\w[\w-]*)=(?:"([^"]*)"|'([^']*)'|(\S+))"#).unwrap());

const TAG_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// An extracted HTML tag (meta or link) with its attributes.
#[derive(Clone)]
pub struct HtmlTag {
   pub tag:   String,
   pub attrs: Vec<(String, String)>,
}

/// Serves from the cache when it can, and otherwise pays for a subrequest to
/// the backend root.
pub async fn fetch_tags(
   host: &str,
   cache: &DecayMap<String, Vec<HtmlTag>>,
   http_client: &Client<HttpConnector, Body>,
   backend_uri: &Uri,
) -> Vec<HtmlTag> {
   let host_key = host.to_owned();
   if let Some(tags) = cache.get(&host_key) {
      return tags;
   }

   let uri = {
      let scheme = backend_uri.scheme_str().unwrap_or("http");
      let authority = backend_uri
         .authority()
         .map_or("localhost", Authority::as_str);
      format!("{scheme}://{authority}/").parse::<Uri>().ok()
   };

   let Some(uri) = uri else {
      return Vec::new();
   };

   let req = Request::builder()
      .uri(uri)
      .header(header::HOST, host)
      .header(header::USER_AGENT, "bagel/0.1 (tag-fetcher)")
      .body(Body::empty());

   let Ok(req) = req else {
      return Vec::new();
   };

   let resp = match tokio::time::timeout(TAG_FETCH_TIMEOUT, http_client.request(req)).await {
      Ok(Ok(response)) => response,
      Ok(Err(err)) => {
         tracing::debug!(host, error = %err, "tag fetch request failed");
         return Vec::new();
      },
      Err(_) => {
         tracing::debug!(host, "tag fetch request timed out");
         return Vec::new();
      },
   };

   let content_type = resp
      .headers()
      .get(header::CONTENT_TYPE)
      .and_then(|hv| hv.to_str().ok())
      .unwrap_or("");
   if !content_type.contains("text/html") {
      cache.set(host.to_owned(), Vec::new());
      return Vec::new();
   }

   let body_bytes = if let Ok(Ok(buf)) = tokio::time::timeout(
      TAG_FETCH_TIMEOUT,
      Limited::new(resp.into_body(), 256 * 1024).collect(),
   )
   .await
   {
      buf.to_bytes()
   } else {
      cache.set(host.to_owned(), Vec::new());
      return Vec::new();
   };

   let html = String::from_utf8_lossy(&body_bytes);
   let tags = extract_tags(&html);
   cache.set(host.to_owned(), tags.clone());
   tags
}

pub type TagAttrMaps = Vec<BTreeMap<String, String>>;

/// Convert extracted tags to attribute maps for the template layer.
#[must_use]
pub fn tags_to_template_values(tags: &[HtmlTag]) -> (TagAttrMaps, TagAttrMaps) {
   let mut meta_tags = Vec::new();
   let mut link_tags = Vec::new();

   for tag in tags {
      let attrs: BTreeMap<String, String> = tag.attrs.iter().cloned().collect();
      match tag.tag.as_str() {
         "meta" => meta_tags.push(attrs),
         "link" => link_tags.push(attrs),
         _ => {},
      }
   }

   (meta_tags, link_tags)
}

const SAFE_META_PREFIXES: &[&str] = &[
   "og:",
   "fb:",
   "twitter:",
   "profile:",
   "vcs:",
   "forge:",
   "citation_",
];

const SAFE_META_NAMES: &[&str] = &[
   "theme-color",
   "color-scheme",
   "origin-trials",
   "application-name",
   "origin",
   "author",
   "creator",
   "contact",
   "title",
   "description",
   "thumbnail",
   "rating",
   "license",
   "license:uri",
   "rights",
   "rights-standard",
   "go-import",
   "go-source",
   "apple-itunes-app",
   "appstore:bundle_id",
   "appstore:developer_url",
   "appstore:store_id",
   "google-play-app",
   "verify-v1",
   "google-site-verification",
   "p:domain_verify",
   "yandex-verification",
   "alexaverifyid",
   "keywords",
   "robots",
   "google",
   "googlebot",
   "bingbot",
   "pinterest",
   "Slurp",
];

const SAFE_LINK_RELS: &[&str] = &[
   "icon",
   "shortcut icon",
   "apple-touch-icon",
   "apple-touch-icon-precomposed",
   "alternate",
   "canonical",
   "manifest",
   "author",
   "me",
   "license",
   "copyright",
   "privacy-policy",
   "terms-of-service",
   "search",
   "dns-prefetch",
   "preconnect",
];

const SAFE_ATTRIBUTES: &[&str] = &[
   "name",
   "property",
   "content",
   "charset",
   "http-equiv",
   "rel",
   "href",
   "type",
   "hreflang",
   "media",
   "sizes",
   "crossorigin",
];

/// Fetch and extract safe meta/link tags from an HTML response body.
/// Uses regex to avoid pulling in a full HTML parser (scraper/html5ever).
pub fn extract_tags(html_body: &str) -> Vec<HtmlTag> {
   // Only parse the <head> section to avoid processing large bodies
   let head_content = extract_head(html_body);
   let body = head_content.unwrap_or(html_body);

   let mut tags = Vec::new();

   for cap in TAG_RE.captures_iter(body) {
      let tag_name = cap[1].to_lowercase();
      let attr_str = &cap[2];

      let mut raw_attrs = Vec::new();
      for attr_cap in ATTR_RE.captures_iter(attr_str) {
         let key = attr_cap[1].to_lowercase();
         let value = attr_cap
            .get(2)
            .or_else(|| attr_cap.get(3))
            .or_else(|| attr_cap.get(4))
            .map_or("", |mat| mat.as_str());
         raw_attrs.push((key, value.to_owned()));
      }

      match tag_name.as_str() {
         "meta" => {
            let name = raw_attrs
               .iter()
               .find(|(key, _)| key == "name" || key == "property")
               .map_or("", |(_, val)| val.as_str());

            if !is_safe_meta_name(name) {
               continue;
            }

            let safe_attrs: Vec<(String, String)> = raw_attrs
               .into_iter()
               .filter(|(key, _)| SAFE_ATTRIBUTES.contains(&key.as_str()))
               .collect();

            if !safe_attrs.is_empty() {
               tags.push(HtmlTag {
                  tag:   "meta".to_owned(),
                  attrs: safe_attrs,
               });
            }
         },
         "link" => {
            let rel = raw_attrs
               .iter()
               .find(|(key, _)| key == "rel")
               .map_or("", |(_, val)| val.as_str());

            if !SAFE_LINK_RELS.contains(&rel) {
               continue;
            }

            let safe_attrs: Vec<(String, String)> = raw_attrs
               .into_iter()
               .filter(|(key, _)| {
                  SAFE_ATTRIBUTES.contains(&key.as_str()) || key == "href" || key == "rel"
               })
               .collect();

            if !safe_attrs.is_empty() {
               tags.push(HtmlTag {
                  tag:   "link".to_owned(),
                  attrs: safe_attrs,
               });
            }
         },
         _ => {},
      }
   }

   tags
}

/// Extract the content of the <head> section (case-insensitive, no allocation).
fn extract_head(html: &str) -> Option<&str> {
   let bytes = html.as_bytes();
   let start = bytes
      .windows(5)
      .position(|win| win.eq_ignore_ascii_case(b"<head"))?;
   let start = html[start..].find('>')? + start + 1;
   let end = bytes[start..]
      .windows(7)
      .position(|win| win.eq_ignore_ascii_case(b"</head>"))
      .map(|idx| idx + start)?;
   Some(&html[start..end])
}

fn is_safe_meta_name(name: &str) -> bool {
   if name.is_empty() {
      return false;
   }
   for prefix in SAFE_META_PREFIXES {
      if name.starts_with(prefix) {
         return true;
      }
   }
   SAFE_META_NAMES.contains(&name)
}
