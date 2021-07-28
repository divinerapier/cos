pub fn encode_uri_component(s: &str, excluded: Option<&[u8]>) -> String {
    let mut b = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')' => {
                b.push(c);
            }
            'a'..='z' | 'A'..='Z' | '0'..='9' => {
                b.push(c);
            }
            _ => {
                let mut flag = false;
                if let Some(excluded) = excluded.as_ref() {
                    flag = !excluded.is_empty() && excluded.contains(&(c as u8))
                }
                if flag {
                    b.push(c);
                } else {
                    b.push_str(&format! {"%{:02X}",c as u8});
                }
            }
        };
    }
    b
}

pub fn safe_url_encode(s: &str) -> String {
    let mut s = encode_uri_component(s, None);
    if s.contains('!') {
        s = s.replace('!', "%21");
    }
    if s.contains('\'') {
        s = s.replace('\'', "%27");
    }
    if s.contains('(') {
        s = s.replace('(', "%28");
    }
    if s.contains(')') {
        s = s.replace(')', "%29");
    }
    if s.contains('*') {
        s = s.replace('*', "%2A");
    }
    s
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_no_exclude() {
        let cases = vec![
            ("host.com", "host.com"),
            ("host.com/", "host.com%2F"),
            ("host.com&", "host.com%26"),
            ("host.com=", "host.com%3D"),
            ("host.com/&", "host.com%2F%26"),
            ("host.com/=", "host.com%2F%3D"),
            ("host.com&=", "host.com%26%3D"),
            ("host.com/&=", "host.com%2F%26%3D"),
        ];
        for c in cases {
            let result = encode_uri_component(c.0, None);
            println!("{} -> {} -> {}", c.0, result, c.1);
            assert_eq!(result, c.1);
        }
    }

    #[test]
    fn test_exclude() {
        let cases = vec![
            ("host.com", "host.com"),
            ("host.com/", "host.com/"),
            ("host.com&", "host.com%26"),
            ("host.com=", "host.com%3D"),
            ("host.com/&", "host.com/%26"),
            ("host.com/=", "host.com/%3D"),
            ("host.com&=", "host.com%26%3D"),
            ("host.com/&=", "host.com/%26%3D"),
        ];
        let exclude: Vec<u8> = vec!['/' as u8];
        for c in cases {
            let result = encode_uri_component(c.0, Some(&exclude));
            println!("{} -> {} -> {}", c.0, result, c.1);
            assert_eq!(result, c.1);
        }
    }

    #[test]
    fn test_safe_url_encode() {
        let cases = vec![
            ("host.com", "host.com"),
            ("host.com/", "host.com%2F"),
            ("host.com&", "host.com%26"),
            ("host.com=", "host.com%3D"),
            ("host.com/&\\", "host.com%2F%26%5C"),
            ("host.com/=\\(", "host.com%2F%3D%5C%28"),
            ("host.com&=)(", "host.com%26%3D%29%28"),
            ("host.com/&=!", "host.com%2F%26%3D%21"),
        ];

        for (input, output) in cases {
            assert_eq!(output, safe_url_encode(input));
        }
    }
}
