use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};
use serde_json::{Map, Value};
use std::io::{self, Write};

struct PyFormatter;

impl Formatter for PyFormatter {
    fn write_f64<W: ?Sized + Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        writer.write_all(py_float_repr(value).as_bytes())
    }

    fn write_f32<W: ?Sized + Write>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        self.write_f64(writer, value as f64)
    }

    fn write_string_fragment<W: ?Sized + Write>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            if (c as u32) < 0x7f {
                continue;
            }
            writer.write_all(&fragment.as_bytes()[start..i])?;
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                write!(writer, "\\u{unit:04x}")?;
            }
            start = i + c.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    value.serialize(&mut Serializer::with_formatter(&mut out, PyFormatter))?;
    Ok(out)
}

pub fn to_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
    to_vec(value).map(|bytes| String::from_utf8(bytes).expect("ensure_ascii output is ASCII"))
}

pub fn py_float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let exp: i32 = exp.parse().expect("{:e} exponent is an integer");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let sign = if x < 0.0 { "-" } else { "" };
    if !(-4..16).contains(&exp) {
        let (head, tail) = digits.split_at(1);
        let frac = if tail.is_empty() { String::new() } else { format!(".{tail}") };
        let esign = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{head}{frac}e{esign}{:02}", exp.abs());
    }
    if exp < 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-exp - 1) as usize));
    }
    let point = exp as usize + 1;
    if digits.len() <= point {
        format!("{sign}{digits}{}.0", "0".repeat(point - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..point], &digits[point..])
    }
}

pub fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "True" } else { "False" }.into(),
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i.to_string(),
            (None, Some(u)) => u.to_string(),
            _ => py_float_repr(n.as_f64().unwrap_or(f64::NAN)),
        },
        other => other.to_string(),
    }
}

pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

pub fn text<'a>(map: &'a Map<String, Value>, key: &str) -> &'a str {
    map.get(key).and_then(Value::as_str).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_print_like_python_repr() {
        let cases = [
            (1800.0, "1800.0"),
            (0.1, "0.1"),
            (-55.0, "-55.0"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1.5e16, "1.5e+16"),
            (1e16, "1e+16"),
            (9999999999999998.0, "9999999999999998.0"),
            (123456.789, "123456.789"),
            (1792197973.846, "1792197973.846"),
            (2.5e-300, "2.5e-300"),
            (1e100, "1e+100"),
            (-0.0, "-0.0"),
        ];
        for (x, want) in cases {
            assert_eq!(py_float_repr(x), want, "{x}");
        }
    }

    #[test]
    fn strings_are_ascii_escaped_like_ensure_ascii() {
        let v = json!({"s": "caf\u{e9} \u{1f600} a\"b\\c\nd\u{7f}\u{1}", "n": [1, 2.0, null, true]});
        assert_eq!(
            to_string(&v).unwrap(),
            r#"{"s":"caf\u00e9 \ud83d\ude00 a\"b\\c\nd\u007f\u0001","n":[1,2.0,null,true]}"#
        );
    }
}
