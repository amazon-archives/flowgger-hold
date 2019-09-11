use super::Encoder;
use crate::flowgger::config::Config;
use crate::flowgger::record::{Record, SDValue};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct LTSVEncoder {
    extra: Vec<(String, String)>,
}

impl LTSVEncoder {
    pub fn new(config: &Config) -> LTSVEncoder {
        let extra = match config.lookup("output.ltsv_extra") {
            None => Vec::new(),
            Some(extra) => extra
                .as_table()
                .expect("output.ltsv_extra must be a list of key/value pairs")
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_owned(),
                        v.as_str()
                            .expect("output.ltsv_extra values must be strings")
                            .to_owned(),
                    )
                })
                .collect(),
        };
        LTSVEncoder { extra }
    }
}

fn escape_string(field: &str) -> String {
    if field.chars().any(|s| s == '\n' || s == '\t' || s == ':') {
        field
            .replace("\n", " ")
            .replace("\t", " ")
            .replace(":", "_")
    } else {
        field.to_string()
    }
}

struct LTSVString {
    out: BTreeMap<String, String>,
}

impl LTSVString {
    pub fn new() -> LTSVString {
        LTSVString {
            out: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: &str, value: &str) {
        let key_escaped = &escape_string(key);
        let value_escaped = &escape_string(value);
        self.out
            .entry(key_escaped.to_string())
            .and_modify(|v| *v = value_escaped.to_string())
            .or_insert_with(|| value_escaped.to_string());
    }

    pub fn finalize(self) -> String {
        let mut final_line = String::new();
        for (key, value) in &self.out {
            final_line.push_str(&format!("{}:{}\t", &key, &value))
        }
        final_line.trim_end().to_string()
    }
}

impl Encoder for LTSVEncoder {
    fn encode(&self, record: Record) -> Result<Vec<u8>, &'static str> {
        let mut res = LTSVString::new();
        if let Some(sd) = record.sd {
            for &(ref name, ref value) in &sd.pairs {
                let name = if (*name).starts_with('_') {
                    &name[1..] as &str
                } else {
                    name as &str
                };
                match *value {
                    SDValue::String(ref value) => res.insert(name, value),
                    SDValue::Bool(ref value) => res.insert(name, &value.to_string()),
                    SDValue::F64(ref value) => res.insert(name, &value.to_string()),
                    SDValue::I64(ref value) => res.insert(name, &value.to_string()),
                    SDValue::U64(ref value) => res.insert(name, &value.to_string()),
                    SDValue::Null => res.insert(name, ""),
                }
            }
        }
        for &(ref name, ref value) in &self.extra {
            let name = if (*name).starts_with('_') {
                &name[1..] as &str
            } else {
                name as &str
            };
            res.insert(name, value);
        }
        res.insert("host", &record.hostname);
        res.insert("time", &record.ts.to_string());
        if let Some(msg) = record.msg {
            res.insert("message", &msg);
        }
        if let Some(full_msg) = record.full_msg {
            res.insert("full_message", &full_msg);
        }
        if let Some(severity) = record.severity {
            res.insert("level", &format!("{}", severity));
        }
        if let Some(facility) = record.facility {
            res.insert("facility", &format!("{}", facility));
        }
        if let Some(appname) = record.appname {
            res.insert("appname", &appname);
        }
        if let Some(procid) = record.procid {
            res.insert("procid", &procid);
        }
        if let Some(msgid) = record.msgid {
            res.insert("msgid", &msgid);
        }
        Ok(res.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flowgger::record::{SDValue, StructuredData};

    #[test]
    fn test_ltsv_encoder() {
        let expected_msg =
            "a_key:bar\tappname:appname\tfull_message:Backtrace   here with more\thost:example.org\tlevel:1\tmessage:A short message\tmsgid:msg_id\tprocid:44\tsome_info:foo\ttime:1385053862.3072";
        let config = Config::from_string("[output.ltsv_extra]\na_key = \"bar\"").unwrap();
        let sd = StructuredData {
            sd_id: Some("someid".to_string()),
            pairs: vec![("some_info".to_string(), SDValue::String("foo".to_string()))],
        };
        let record = Record {
            ts: 1385053862.3072,
            hostname: "example.org".to_string(),
            facility: None,
            severity: Some(1),
            appname: Some("appname".to_string()),
            procid: Some("44".to_string()),
            msgid: Some("msg_id".to_string()),
            msg: Some("A short message".to_string()),
            full_msg: Some("Backtrace\n\n here\nwith more".to_string()),
            sd: Some(sd),
        };
        let encoder = LTSVEncoder::new(&config);
        assert_eq!(
            String::from_utf8_lossy(&encoder.encode(record).unwrap()),
            expected_msg
        );
    }

    #[test]
    fn test_ltsv_encoder_replace_extra() {
        let expected_msg =
            "host:example.org\tlevel:1\tmessage:A short message\tsome_info:bar\ttime:1385053862.3072";
        let config = Config::from_string("[output.ltsv_extra]\n_some_info = \"bar\"").unwrap();
        let sd = StructuredData {
            sd_id: Some("someid".to_string()),
            pairs: vec![("_some_info".to_string(), SDValue::String("foo".to_string()))],
        };
        let record = Record {
            ts: 1385053862.3072,
            hostname: "example.org".to_string(),
            facility: None,
            severity: Some(1),
            appname: None,
            procid: None,
            msgid: None,
            msg: Some("A short message".to_string()),
            full_msg: None,
            sd: Some(sd),
        };
        let encoder = LTSVEncoder::new(&config);
        assert_eq!(
            String::from_utf8_lossy(&encoder.encode(record).unwrap()),
            expected_msg
        );
    }

    #[test]
    #[should_panic(expected = "output.ltsv_extra must be a list of key/value pairs")]
    fn test_ltsv_encoder_config_extra_should_be_section() {
        let _encoder =
            LTSVEncoder::new(&Config::from_string("[output]\nltsv_extra = \"bar\"").unwrap());
    }

    #[test]
    #[should_panic(expected = "output.ltsv_extra values must be strings")]
    fn test_ltsv_encoder_config_extra_bad_type() {
        let _encoder =
            LTSVEncoder::new(&Config::from_string("[output.ltsv_extra]\n_some_info = 42").unwrap());
    }
}
