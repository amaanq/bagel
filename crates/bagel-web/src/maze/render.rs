use std::sync::LazyLock;

use super::keys::frame;

/// Bundled word corpus for deterministic prose and link paths. Lowercase
/// ASCII letters only, so generated text and paths never need escaping and
/// always satisfy the maze path grammar.
const CORPUS_WORDS: &str =
   "\
   archive article assembly atlas author balance battery border branch bridge cabinet canvas \
    capital carbon catalog cellar chamber channel chapter charter circuit cistern climate colony \
    column compass copper corridor cottage council courier crystal current cypress diagram \
    dispatch domain drawer dynamo editor element engine estate fabric factory fallow feather \
    ferry figure filament flint forge fortress fountain gallery garden garrison glacier granite \
    hamlet harbor harvest hollow index ingot island journal junction keystone lantern ledger \
    library lookout machine manual marble meadow meridian mineral monument morning mosaic \
    notebook orchard outpost paper parcel passage pattern pillar pioneer portal prairie quarry \
    record region register reserve river saddle satchel seaboard section sediment signal silver \
    spindle station stone summit survey terrace textile timber tower traverse tribune tunnel \
    valley vault vessel village vineyard wagon warehouse willow window workshop";

static CORPUS: LazyLock<Box<[&str]>> =
   LazyLock::new(|| CORPUS_WORDS.split_ascii_whitespace().collect());

/// Deterministic keystream built from HMAC-SHA256 in counter mode. Both the
/// authenticated and decoy seeds feed this same generator, so page structure
/// cannot distinguish them.
struct HmacRng {
   key:     ring::hmac::Key,
   counter: u64,
   block:   [u8; 32],
   used:    usize,
}

impl HmacRng {
   fn new(seed: [u8; 32]) -> Self {
      Self {
         key:     ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &seed),
         counter: 0,
         block:   [0; 32],
         used:    32,
      }
   }

   fn next_u32(&mut self) -> u32 {
      if self.used + 4 > 32 {
         self.block = ring::hmac::sign(&self.key, &self.counter.to_be_bytes())
            .as_ref()
            .try_into()
            .expect("hmac output is 32 bytes");
         self.counter += 1;
         self.used = 0;
      }
      let value = u32::from_be_bytes(
         self.block[self.used..self.used + 4]
            .try_into()
            .expect("length checked"),
      );
      self.used += 4;
      value
   }

   fn range(&mut self, lo: u32, hi_inclusive: u32) -> u32 {
      lo + self.next_u32() % (hi_inclusive - lo + 1)
   }

   fn word(&mut self) -> &'static str {
      CORPUS[self.range(0, CORPUS.len() as u32 - 1) as usize]
   }
}

#[derive(Clone, Copy)]
pub struct RenderBudget {
   pub min_links: u32,
   pub max_links: u32,
   pub min_bytes: u32,
   pub max_bytes: u32,
}

/// Derive the deterministic page seed from the render or decoy key and the
/// raw path bytes. Queries are never part of the seed.
#[must_use]
pub fn page_seed(key: &[u8; 32], path_bytes: &[u8]) -> [u8; 32] {
   let mut input = frame(b"bagel maze render v1");
   input.extend_from_slice(&frame(path_bytes));
   let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), &input);
   tag.as_ref().try_into().expect("hmac output is 32 bytes")
}

/// Generate one maze path for a link.
fn generate_path(rng: &mut HmacRng) -> String {
   let segments = rng.range(1, 3);
   let mut path = String::new();
   for index in 0..segments {
      if index > 0 {
         path.push('/');
      }
      path.push_str(rng.word());
      if rng.range(0, 2) == 0 {
         path.push('-');
         path.push_str(rng.word());
      }
   }
   path
}

/// Plan deterministic link paths without rendering.
#[must_use]
pub fn plan_links(seed: [u8; 32], budget: &RenderBudget) -> Vec<String> {
   let mut rng = HmacRng::new(seed);
   let count = rng.range(budget.min_links, budget.max_links);
   std::iter::repeat_with(|| generate_path(&mut rng))
      .take(count as usize)
      .collect()
}

fn push_sentence(html: &mut String, rng: &mut HmacRng) {
   let words = rng.range(6, 16);
   for index in 0..words {
      if index > 0 {
         html.push(' ');
      }
      html.push_str(rng.word());
   }
   html.push_str(". ");
}

/// Render one deterministic maze page.
pub fn render_page<F: FnMut(&str) -> String>(
   seed: [u8; 32],
   budget: &RenderBudget,
   mut mint_link: F,
) -> String {
   let mut rng = HmacRng::new(seed);
   let link_count = rng.range(budget.min_links, budget.max_links);
   let reserve = 128 * link_count + 256;
   let target = rng.range(
      budget.min_bytes,
      budget
         .max_bytes
         .saturating_sub(reserve)
         .max(budget.min_bytes),
   ) as usize;

   let mut html = String::with_capacity(target + reserve as usize);
   html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>");
   html.push_str(rng.word());
   html.push(' ');
   html.push_str(rng.word());
   html.push_str("</title></head><body>");

   let mut links_left = link_count;
   while html.len() < target || links_left > 0 {
      html.push_str("<p>");
      let sentences = rng.range(2, 5);
      for _ in 0..sentences {
         push_sentence(&mut html, &mut rng);
      }
      if links_left > 0 {
         let path = generate_path(&mut rng);
         let href = mint_link(&path);
         html.push_str("<a href=\"");
         html.push_str(&href);
         html.push_str("\">");
         html.push_str(rng.word());
         html.push(' ');
         html.push_str(rng.word());
         html.push_str("</a>. ");
         links_left -= 1;
      }
      html.push_str("</p>");
      if html.len() >= budget.max_bytes as usize - 64 {
         break;
      }
   }

   html.push_str("</body></html>");
   html
}

#[cfg(test)]
mod tests {
   use super::*;

   const BUDGET: RenderBudget = RenderBudget {
      min_links: 8,
      max_links: 16,
      min_bytes: 8192,
      max_bytes: 32_768,
   };

   #[test]
   fn pages_respect_link_and_byte_budgets() {
      for seed_byte in 0..16_u8 {
         let mut links = 0;
         let page = render_page([seed_byte; 32], &BUDGET, |path| {
            links += 1;
            format!("/x/{path}")
         });
         assert!(
            (BUDGET.min_links..=BUDGET.max_links).contains(&links),
            "{links}"
         );
         assert!(page.len() <= BUDGET.max_bytes as usize, "{}", page.len());
         assert!(page.len() >= BUDGET.min_bytes as usize, "{}", page.len());
      }
   }
}
