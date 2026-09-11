use std::path::{
   Path,
   PathBuf,
};

use knead::{
   ast::{
      Literal,
      Radix,
   },
   decode::DecodeScalar,
};

use super::*;
use crate::{
   Bagel,
   Enforcement,
   EnforcementMode,
   web::{
      DeceptionConfig,
      SmearConfig,
   },
};

#[derive(knead_derive::Decode)]
struct Scalars {
   #[knead(argument)]
   text:     String,
   #[knead(property)]
   enabled:  bool,
   #[knead(property)]
   disabled: bool,
   #[knead(property)]
   absent:   Option<String>,
   #[knead(property)]
   signed:   i64,
   #[knead(property)]
   unsigned: u64,
   #[knead(property)]
   ratio:    f64,
   #[knead(property)]
   positive: f64,
   #[knead(property)]
   negative: f64,
   #[knead(property)]
   nan:      f64,
   #[knead(property)]
   zero:     f64,
}

#[test]
#[expect(
   clippy::float_cmp,
   clippy::non_ascii_literal,
   reason = "the decoder must reproduce each literal bit for bit, so a tolerance would hide the \
             rounding this guards against"
)]
fn kdl2_scalars_decode_without_text_conversion() {
   let document = knead::parse(r#"
values café enabled=#true disabled=#false absent=#null signed=-9223372036854775808 unsigned=0xffff_ffff_ffff_ffff ratio=1.25 positive=#inf negative=#-inf "nan"=#nan zero=-0.0
"#).unwrap();
   let decoded: Scalars = node(&document.nodes()[0]).unwrap();
   assert_eq!(decoded.text, "caf\u{e9}");
   assert!(decoded.enabled);
   assert!(!decoded.disabled);
   assert_eq!(decoded.absent, None);
   assert_eq!(decoded.signed, i64::MIN);
   assert_eq!(decoded.unsigned, u64::MAX);
   assert_eq!(decoded.ratio, 1.25);
   assert_eq!(decoded.positive, f64::INFINITY);
   assert_eq!(decoded.negative, f64::NEG_INFINITY);
   assert!(decoded.nan.is_nan());
   assert_eq!(decoded.zero, 0.0);
   assert!(decoded.zero.is_sign_negative());
}

#[test]
fn kdl2_strings_comments_and_ignored_nodes_reach_the_schema() {
   let config = Bagel::parse(
      r##"
deception {
    server """
        first line
        second line
        """
    corpora #"/tmp/corpus"#
    scripts "/tmp/scripts"
    /- invalid #false
    not-found-pct 0x20
    forbidden-pct /- 99 0b1000
}
smear {
    min-delay-ms 25
    max-delay-ms 50
    max-secs 2
    chunk-min 16
    chunk-max 32
    max-concurrent 4
}
defense { enforcement mode=observe table=custom chain-priority=-20 reconcile-interval-secs=2 }
"##,
      Path::new("typed.kdl"),
   )
   .unwrap();
   assert_eq!(config.web.deception, DeceptionConfig {
      corpora:       Some(PathBuf::from("/tmp/corpus")),
      scripts:       Some(PathBuf::from("/tmp/scripts")),
      server:        "first line\nsecond line".into(),
      not_found_pct: 32,
      forbidden_pct: 8,
   });
   assert_eq!(config.web.smear, SmearConfig {
      min_delay_ms:   25,
      max_delay_ms:   50,
      max_secs:       2,
      chunk_min:      16,
      chunk_max:      32,
      max_concurrent: 4,
   });
   assert_eq!(config.defense.enforcement, Enforcement {
      mode:                    EnforcementMode::Observe,
      table:                   "custom".into(),
      chain_priority:          -20,
      reconcile_interval_secs: 2,
   });
}

#[test]
fn node_and_value_annotations_keep_their_source_spans() {
   let text = "(settings)config answer=(u8)0xff { child #true; }";
   let document = knead::parse(text).unwrap();
   let original = &document.nodes()[0];
   assert_eq!(original.type_name.as_ref().unwrap().value, "settings");
   assert_eq!(
      original.type_name.as_ref().unwrap().span.offset(),
      text.find("settings").unwrap()
   );
   assert_eq!(original.name.span.offset(), text.find("config").unwrap());
   assert_eq!(original.span.offset(), 0);
   let property = original.properties.first().unwrap();
   assert_eq!(property.value.type_name.as_ref().unwrap().value, "u8");
   assert_eq!(property.span.offset(), text.find("answer").unwrap());
   let children = original.children.as_ref().unwrap();
   assert_eq!(children.span.offset(), text.find('{').unwrap());
   assert_eq!(children.nodes[0].arguments[0].literal, Literal::Bool(true));
}

#[test]
fn integer_conversion_preserves_the_full_ast_integer_range() {
   for number in [i128::MIN, i128::MAX] {
      let text = format!("number {number}");
      let original = knead::parse(&text).unwrap();
      let value = &original.nodes[0].arguments[0];
      let integer = match &value.literal {
         Literal::Integer(integer) => Some(integer),
         _ => None,
      }
      .expect("expected an integer");
      assert_eq!(integer.radix, Radix::Decimal);
      assert_eq!(integer.digits, number.to_string());
      assert_eq!(i128::decode(value).unwrap(), number);
   }
}

#[test]
fn repeated_properties_keep_the_last_value_and_its_location() {
   let text = "enforcement mode=required mode=observe chain-priority=-5 chain-priority=7";
   let document = knead::parse(text).unwrap();
   let decoded: Enforcement = node(&document.nodes()[0]).unwrap();
   assert_eq!(decoded.mode, EnforcementMode::Observe);
   assert_eq!(decoded.chain_priority, 7);
   let property = document.nodes()[0]
      .properties
      .iter()
      .find(|property| property.name.value == "mode")
      .unwrap();
   assert_eq!(property.name.span.offset(), text.rfind("mode=").unwrap());
   assert_eq!(property.span.offset(), text.rfind("mode=").unwrap());
}

#[test]
fn omitted_fields_keep_existing_configuration_defaults() {
   for text in [
      "deception\nsmear\ndefense { enforcement; }",
      "deception {}\nsmear {}\ndefense { enforcement {} }",
   ] {
      let config = Bagel::parse(text, Path::new("defaults.kdl")).unwrap();
      assert_eq!(config.web.deception, DeceptionConfig::default());
      assert_eq!(config.web.smear, SmearConfig::default());
      assert_eq!(config.defense.enforcement, Enforcement::default());
   }
}

#[test]
fn typed_schemas_reject_unknown_extra_duplicate_and_wrongly_typed_fields() {
   for text in [
      "deception { misspelled 1 }",
      "deception extra=1 {}",
      "deception unexpected {}",
      "deception { server first; server second }",
      "deception { corpora #null }",
      "deception { server 1 }",
      "deception { server first second }",
      "deception { not-found-pct 256 }",
      "deception { not-found-pct -1 }",
      "deception { not-found-pct (u16)20 }",
      "smear { max-secs \"60\" }",
      "smear { max-secs #inf }",
      "smear { chunk-min -1 }",
      "smear { max-secs 18446744073709551616 }",
      "smear { max-secs 1; max-secs 2 }",
      "defense { enforcement mode=unknown }",
      "defense { enforcement mode=#null }",
      "defense { enforcement chain-priority=2147483648 }",
      "defense { enforcement extra=1 }",
      "defense { enforcement { extra 1 } }",
      "defense { enforcement; enforcement }",
   ] {
      let error = Bagel::parse(text, Path::new("invalid.kdl"))
         .err()
         .expect("an unknown, extra, duplicate or wrongly typed field should not decode")
         .to_string();
      assert!(error.contains("invalid.kdl:1:"), "{text}\n{error}");
   }
}

#[test]
fn semantic_validation_still_runs_after_decoding() {
   let config = Bagel::parse(
      "deception { not-found-pct 90; forbidden-pct 20 }\nsmear { min-delay-ms 20; max-delay-ms 10 \
       }\ndefense { enforcement reconcile-interval-secs=0 }",
      Path::new("semantic.kdl"),
   )
   .unwrap();
   assert!(config.web.deception.validate().is_err());
   assert!(config.web.smear.validate().is_err());
   assert!(config.defense.validate().is_err());
}

#[test]
fn decoding_errors_retain_unicode_file_line_and_column_locations() {
   let text = "deception {\n server caf\u{e9}\n not-found-pct 256\n}\n";
   let error = Bagel::parse(text, Path::new("unicode.kdl"))
      .err()
      .expect("an out of range not-found-pct should not decode")
      .to_string();
   let (line, column) = crate::locate(text, text.find("256").unwrap());
   assert!(
      error.contains(&format!("unicode.kdl:{line}:{column}:")),
      "{error}"
   );
}
