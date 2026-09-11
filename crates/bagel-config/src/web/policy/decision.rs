use super::{
   RhaiExpression,
   RuleConfig,
   RuleSettings,
   ThresholdConfig,
};

#[derive(knead_derive::Decode)]
pub(super) struct RuleInput {
   #[knead(argument)]
   name:        String,
   #[knead(property)]
   condition:   Option<RhaiExpression>,
   #[knead(property, default = "none".to_owned())]
   action:      String,
   #[knead(property)]
   http_code:   Option<u16>,
   #[knead(property)]
   pass_action: Option<String>,
   #[knead(property)]
   fail_action: Option<String>,
   #[knead(property(name = "match"))]
   match_re:    Option<String>,
   #[knead(property)]
   rewrite:     Option<String>,
   #[knead(property)]
   backend:     Option<String>,
   #[knead(property)]
   maze:        Option<String>,
   #[knead(property)]
   kind:        Option<String>,
   #[knead(children)]
   children:    Vec<RuleChild>,
}

impl RuleInput {
   pub(super) fn name(&self) -> &str {
      &self.name
   }
}

#[derive(knead_derive::Decode)]
enum RuleChild {
   Condition(#[knead(argument)] RhaiExpression),
   Action(#[knead(argument)] String),
   Challenges(#[knead(arguments)] Vec<String>),
   HttpCode(#[knead(argument)] u16),
   PassAction(#[knead(argument)] String),
   FailAction(#[knead(argument)] String),
   Backend(#[knead(argument)] String),
   Match(#[knead(argument)] String),
   Rewrite(#[knead(argument)] String),
   Kind(#[knead(argument)] String),
   RequestHeaders(Headers),
   ResponseHeaders(Headers),
   Rule(Box<RuleInput>),
}

#[derive(knead_derive::Decode)]
struct Headers {
   #[knead(children)]
   entries: Vec<Header>,
}

#[derive(knead_derive::Decode)]
struct Header {
   #[knead(node_name)]
   name:  String,
   #[knead(argument, default)]
   value: String,
}

impl Headers {
   fn into_pairs(self) -> Vec<(String, String)> {
      self
         .entries
         .into_iter()
         .map(|header| (header.name, header.value))
         .collect()
   }
}

impl From<RuleInput> for RuleConfig {
   fn from(input: RuleInput) -> Self {
      let mut rule = Self {
         name:       input.name,
         condition:  input.condition,
         action:     input.action,
         challenges: Vec::new(),
         settings:   RuleSettings {
            http_code: input.http_code,
            pass_action: input.pass_action,
            fail_action: input.fail_action,
            match_re: input.match_re,
            rewrite: input.rewrite,
            backend: input.backend,
            maze: input.maze,
            kind: input.kind,
            ..RuleSettings::default()
         },
         children:   Vec::new(),
      };
      for child in input.children {
         match child {
            RuleChild::Condition(condition) => rule.condition = Some(condition),
            RuleChild::Action(action) => rule.action = action,
            RuleChild::Challenges(challenges) => rule.challenges.extend(challenges),
            RuleChild::HttpCode(code) => rule.settings.http_code = Some(code),
            RuleChild::PassAction(action) => rule.settings.pass_action = Some(action),
            RuleChild::FailAction(action) => rule.settings.fail_action = Some(action),
            RuleChild::Backend(backend) => rule.settings.backend = Some(backend),
            RuleChild::Match(pattern) => rule.settings.match_re = Some(pattern),
            RuleChild::Rewrite(rewrite) => rule.settings.rewrite = Some(rewrite),
            RuleChild::Kind(kind) => rule.settings.kind = Some(kind),
            RuleChild::RequestHeaders(headers) => {
               rule.settings.request_headers = headers.into_pairs();
            },
            RuleChild::ResponseHeaders(headers) => {
               rule.settings.response_headers = headers.into_pairs();
            },
            RuleChild::Rule(child_rule) => rule.children.push((*child_rule).into()),
         }
      }
      rule
   }
}

#[derive(knead_derive::Decode)]
pub(super) struct ThresholdInput {
   #[knead(argument)]
   value:       u32,
   #[knead(property)]
   action:      String,
   #[knead(property)]
   http_code:   Option<u16>,
   #[knead(property)]
   pass_action: Option<String>,
   #[knead(property)]
   fail_action: Option<String>,
   #[knead(property(name = "match"))]
   match_re:    Option<String>,
   #[knead(property)]
   rewrite:     Option<String>,
   #[knead(property)]
   backend:     Option<String>,
   #[knead(property)]
   maze:        Option<String>,
   #[knead(property)]
   kind:        Option<String>,
   #[knead(children)]
   children:    Vec<ThresholdChild>,
}

#[derive(knead_derive::Decode)]
enum ThresholdChild {
   Challenges(#[knead(arguments)] Vec<String>),
   HttpCode(#[knead(argument)] u16),
   PassAction(#[knead(argument)] String),
   FailAction(#[knead(argument)] String),
}

impl From<ThresholdInput> for ThresholdConfig {
   fn from(input: ThresholdInput) -> Self {
      let mut threshold = Self {
         value:      input.value,
         action:     input.action,
         challenges: Vec::new(),
         settings:   RuleSettings {
            http_code: input.http_code,
            pass_action: input.pass_action,
            fail_action: input.fail_action,
            match_re: input.match_re,
            rewrite: input.rewrite,
            backend: input.backend,
            maze: input.maze,
            kind: input.kind,
            ..RuleSettings::default()
         },
      };
      for child in input.children {
         match child {
            ThresholdChild::Challenges(challenges) => threshold.challenges.extend(challenges),
            ThresholdChild::HttpCode(code) => threshold.settings.http_code = Some(code),
            ThresholdChild::PassAction(action) => threshold.settings.pass_action = Some(action),
            ThresholdChild::FailAction(action) => threshold.settings.fail_action = Some(action),
         }
      }
      threshold
   }
}
