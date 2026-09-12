use std::collections::BTreeMap;

use maud::{
   DOCTYPE,
   Markup,
   PreEscaped,
   html,
};

use crate::config::{
   CustomTheme,
   LinkConfig,
};

const DOCUMENT_CSS: &str = include_str!("../assets/document.css");
const WIDGET_CSS: &str = include_str!("../assets/widget.css");

/// Which embedded look the challenge and error pages wear.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Theme {
   #[default]
   Gruvbox,
   Minimal,
}

impl Theme {
   #[must_use]
   pub const fn as_str(self) -> &'static str {
      match self {
         Self::Gruvbox => "gruvbox",
         Self::Minimal => "minimal",
      }
   }

   /// `theme-color` for the light `prefers-color-scheme` slot.
   #[must_use]
   pub const fn light_theme_color(self) -> &'static str {
      match self {
         Self::Gruvbox => "#fbf1c7",
         Self::Minimal => "#ffffff",
      }
   }

   /// `theme-color` for the dark `prefers-color-scheme` slot.
   #[must_use]
   pub const fn dark_theme_color(self) -> &'static str {
      match self {
         Self::Gruvbox => "#282828",
         Self::Minimal => "#ffffff",
      }
   }
}

impl From<Option<&str>> for Theme {
   fn from(name: Option<&str>) -> Self {
      match name {
         Some("minimal") => Self::Minimal,
         _ => Self::Gruvbox,
      }
   }
}

/// Whether a widget draws a visible card or only carries the machinery a
/// challenge needs to prove itself.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Presentation {
   Card,
   Hidden,
}

/// What the bundled loader reads off the host element to drive a challenge.
pub struct LoaderData {
   pub challenge:  String,
   pub difficulty: u32,
   pub verify_url: String,
   /// Solve on the live page instead of reloading once verified.
   pub background: bool,
}

/// One challenge contribution, rendered standalone or inside an origin page.
pub struct Widget {
   pub body:         Markup,
   pub presentation: Presentation,
   /// Module URL this widget needs loaded, if any.
   pub script:       Option<&'static str>,
   pub loader:       Option<LoaderData>,
}

impl Widget {
   #[must_use]
   pub const fn card(body: Markup) -> Self {
      Self {
         body,
         presentation: Presentation::Card,
         script: None,
         loader: None,
      }
   }

   #[must_use]
   pub fn hidden() -> Self {
      Self {
         body:         html! {},
         presentation: Presentation::Hidden,
         script:       None,
         loader:       None,
      }
   }

   #[must_use]
   pub fn driven_by(mut self, script: &'static str, loader: LoaderData) -> Self {
      self.script = Some(script);
      self.loader = Some(loader);
      self
   }
}

/// The chrome every challenge card draws around its own markup.
pub struct Chrome<'a> {
   pub title:   &'a str,
   pub message: &'a str,
   pub links:   &'a [LinkConfig],
   pub logo:    Option<&'a str>,
}

const NOSCRIPT: &str = "JavaScript is required to complete this challenge. Please enable \
                        JavaScript and reload the page.";

/// Map one `challenge-template` property to the custom property it drives.
/// `color-scheme` is not a `--bagel-*` token and is handled separately.
fn theme_var(name: &str) -> Option<&'static str> {
   match name {
      "fg" => Some("--bagel-fg"),
      "bg" => Some("--bagel-bg"),
      "accent" => Some("--bagel-accent"),
      "card-bg" => Some("--bagel-card-bg"),
      "border" => Some("--bagel-border"),
      "error" => Some("--bagel-error"),
      "title-color" => Some("--bagel-title-color"),
      "link-color" => Some("--bagel-link-color"),
      "radius" => Some("--bagel-radius"),
      "font" => Some("--bagel-font"),
      _ => None,
   }
}

/// Inline style carrying the operator's `challenge-template` overrides.
/// Values were validated at load (hex colors, plain lengths, or a restricted
/// font stack) and maud escapes them again here, so a hostile string cannot
/// break out of the attribute. `None` when there is nothing to override, so
/// pages without a custom theme render no empty `style` attribute.
fn theme_style(custom: &CustomTheme) -> Option<String> {
   let mut out = String::new();
   for var in &custom.vars {
      if let Some(property) = theme_var(&var.name) {
         out.push_str(property);
         out.push(':');
         out.push_str(&var.value);
         out.push(';');
      }
   }
   if let Some(scheme) = custom.get("color-scheme") {
      out.push_str("color-scheme:");
      out.push_str(scheme);
      out.push(';');
   }
   (!out.is_empty()).then_some(out)
}

/// Draw the shared card, with one challenge's own markup between the message
/// and the footer links.
#[must_use]
pub fn card(chrome: &Chrome<'_>, extra: &Markup) -> Markup {
   html! {
      div class="card" {
         @if let Some(logo) = chrome.logo.filter(|logo| !logo.is_empty()) {
            img class="logo" src=(logo) alt="Logo" decoding="async";
         }
         h1 { (chrome.title) }
         div class="spinner" role="status" aria-label="Verifying" {}
         p { (chrome.message) }
         noscript { p { (NOSCRIPT) } }
         (extra)
         @if !chrome.links.is_empty() {
            nav class="links" aria-label="Related links" {
               @for link in chrome.links {
                  a href=(link.url) { (link.name) }
               }
            }
         }
      }
   }
}

/// Everything the interstitial draws, already resolved to plain values.
pub struct ChallengePage<'a> {
   pub title:     &'a str,
   pub meta_tags: Vec<&'a BTreeMap<String, String>>,
   pub link_tags: Vec<&'a BTreeMap<String, String>>,
   pub widget:    Widget,
}

#[must_use]
pub fn render_document(theme: Theme, custom: &CustomTheme, page: &ChallengePage<'_>) -> String {
   html! {
      (DOCTYPE)
      html lang="en" {
         head {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1";
            meta name="color-scheme" content=(custom.get("color-scheme").unwrap_or("light dark"));
            meta name="theme-color" media="(prefers-color-scheme: light)" content=(custom.get("bg").unwrap_or_else(|| theme.light_theme_color()));
            meta name="theme-color" media="(prefers-color-scheme: dark)" content=(custom.get("bg").unwrap_or_else(|| theme.dark_theme_color()));
            title { (page.title) }
            style { (PreEscaped(DOCUMENT_CSS)) (PreEscaped(WIDGET_CSS)) }
            (render_tags("meta", &page.meta_tags))
            (render_tags("link", &page.link_tags))
         }
         body class="bagel-widget" data-theme=(theme.as_str()) style=[theme_style(custom)] {
            (host(&page.widget, None))
            (script_tag(&page.widget))
         }
      }
   }
   .into_string()
}

/// Render a widget for splicing into a page an origin produced.
#[must_use]
pub fn render_embed(theme: Theme, custom: &CustomTheme, widget: &Widget) -> String {
   let shadow = (widget.presentation == Presentation::Card).then(|| {
      html! {
         template shadowrootmode="open" {
            style { (PreEscaped(WIDGET_CSS)) }
            div class="bagel-widget" data-theme=(theme.as_str()) style=[theme_style(custom)] { (widget.body) }
         }
      }
   });

   html! {
      (host(widget, shadow.as_ref()))
      (script_tag(widget))
   }
   .into_string()
}

fn host(widget: &Widget, shadow: Option<&Markup>) -> Markup {
   let hidden = widget.presentation == Presentation::Hidden;
   let loader = widget.loader.as_ref();
   html! {
      bagel-challenge
         hidden[hidden]
         data-challenge=[loader.map(|data| &data.challenge)]
         data-difficulty=[loader.map(|data| data.difficulty)]
         data-verify-url=[loader.map(|data| &data.verify_url)]
         data-mode=[loader.and_then(|data| data.background.then_some("background"))]
      {
         @match shadow {
            Some(markup) => (markup),
            None => (widget.body),
         }
      }
   }
}

fn script_tag(widget: &Widget) -> Markup {
   html! {
      @if let Some(src) = widget.script {
         script type="module" src=(src) {}
      }
   }
}

#[must_use]
pub fn render_error(
   theme: Theme,
   custom: &CustomTheme,
   status_code: u16,
   title: &str,
   message: &str,
   error: Option<&str>,
) -> String {
   html! {
      (DOCTYPE)
      html lang="en" {
         head {
            meta charset="utf-8";
            meta name="viewport" content="width=device-width, initial-scale=1";
            meta name="color-scheme" content=(custom.get("color-scheme").unwrap_or("light dark"));
            meta name="theme-color" media="(prefers-color-scheme: light)" content=(custom.get("bg").unwrap_or_else(|| theme.light_theme_color()));
            meta name="theme-color" media="(prefers-color-scheme: dark)" content=(custom.get("bg").unwrap_or_else(|| theme.dark_theme_color()));
            title { (title) }
            style { (PreEscaped(DOCUMENT_CSS)) (PreEscaped(WIDGET_CSS)) }
         }
         body class="bagel-widget" data-theme=(theme.as_str()) style=[theme_style(custom)] {
            main class="card" {
               div class="code" { (status_code) }
               h1 { (title) }
               p { (message) }
               @if let Some(detail) = error.filter(|detail| !detail.is_empty()) {
                  p class="detail" { (detail) }
               }
            }
         }
      }
   }
   .into_string()
}

/// Attribute names come from config rather than from the source, which maud
/// cannot express, so these tags are built by hand and every name is checked.
fn render_tags(name: &str, tags: &[&BTreeMap<String, String>]) -> Markup {
   let mut out = String::new();

   for attrs in tags {
      out.push('<');
      out.push_str(name);
      for (key, value) in *attrs {
         if !is_attr_name(key) {
            continue;
         }
         out.push(' ');
         out.push_str(key);
         out.push_str("=\"");
         out.push_str(&html! { (value) }.into_string());
         out.push('"');
      }
      out.push('>');
   }

   PreEscaped(out)
}

fn is_attr_name(key: &str) -> bool {
   !key.is_empty()
      && key
         .bytes()
         .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}
