//! Simple template engine for response customization.
//! Supports variable substitution, conditionals, and date formatting.
//!
//! Variables: {{variable_name}}
//! Date: {{date}} {{date:%Y-%m-%d}} {{date:%a, %d %b %Y %H:%M:%S GMT}}
//! Conditionals: {{#if variable}}content{{/if}}
//! Defaults: {{variable|default_value}}

pub fn render_template(
    template: &str,
    vars: &std::collections::HashMap<String, String>,
) -> crate::Result<String> {
    render_template_depth(template, vars, 0)
}

#[derive(Debug, Clone, Copy)]
struct ConditionalBlock {
    start: usize,
    content_start: usize,
    end_start: usize,
}

fn render_template_depth(
    template: &str,
    vars: &std::collections::HashMap<String, String>,
    depth: usize,
) -> crate::Result<String> {
    const MAX_DEPTH: usize = 16;
    if depth >= MAX_DEPTH {
        return Err(crate::Error::Config(format!(
            "template recursion limit ({}) reached",
            MAX_DEPTH
        )));
    }

    // Process escape sequences BEFORE variable substitution to prevent
    // attacker-controlled values from injecting control characters
    let mut result = template
        .replace("\\r\\n", "\r\n")
        .replace("\\n", "\n")
        .replace("\\t", "\t");

    // Process conditionals first: {{#if var}}content{{/if}}.
    //
    // `search_from` only ever advances PAST each rendered replacement, so the
    // substituted (attacker-controlled) variable values that a conditional may
    // expand into are never re-scanned for further `{{#if}}` directives. Without
    // this, an attacker Host/URI value like `{{#if x}}...{{/if}}` would be
    // re-interpreted as template syntax (server-side template injection) and the
    // re-scan would enable quadratic-work amplification. Nested conditionals in
    // the ORIGINAL template content are still handled by the recursive render.
    let mut search_from = 0;
    while let Some(rel_start) = result[search_from..].find("{{#if ") {
        let start = search_from + rel_start;
        let Some(name_end_offset) = result[start + 6..].find("}}") else {
            break;
        };
        let name_end = start + 6 + name_end_offset;

        let var_name = &result[start + 6..name_end];
        let Some(block) = find_matching_conditional(&result, start) else {
            break;
        };

        let content = &result[block.content_start..block.end_start];
        let var_exists = vars.get(var_name).map(|v| !v.is_empty()).unwrap_or(false);

        let replacement = if var_exists {
            render_template_depth(content, vars, depth + 1)?
        } else {
            String::new()
        };
        // Resume scanning after the rendered replacement, never inside it.
        search_from = block.start + replacement.len();
        result = format!(
            "{}{}{}",
            &result[..block.start],
            replacement,
            &result[block.end_start + 7..]
        );
    }

    // Process variables with defaults: {{var|default}}.
    //
    // Single forward pass: each `{{...}}` is substituted exactly once and the
    // substituted value is appended literally, never re-scanned. Re-scanning
    // would let an attacker-controlled variable value (e.g. the HTTP Host or
    // request URI) that itself contains `{{...}}` trigger infinite
    // re-substitution or unbounded string growth — a remote DoS.
    let mut output = String::with_capacity(result.len());
    let mut rest = result.as_str();
    loop {
        let Some(start) = rest.find("{{") else {
            output.push_str(rest);
            break;
        };

        if rest[start..].starts_with("{{#") || rest[start..].starts_with("{{/") {
            output.push_str(rest);
            break;
        }

        let Some(end_offset) = rest[start + 2..].find("}}") else {
            output.push_str(rest);
            break;
        };
        let end = start + 2 + end_offset;

        let expr = &rest[start + 2..end];

        let value = if expr == "date" || expr.starts_with("date:") {
            let fmt = expr.strip_prefix("date:").unwrap_or("%Y-%m-%d %H:%M:%S");
            match std::panic::catch_unwind(|| crate::faketime::fake_now().format(fmt).to_string()) {
                Ok(value) => value,
                Err(_) => {
                    return Err(crate::Error::Config(format!(
                        "invalid date format '{}' in template",
                        fmt
                    )));
                }
            }
        } else if expr.contains('|') {
            let parts: Vec<&str> = expr.splitn(2, '|').collect();
            let var_name = parts[0];
            let default = parts[1];
            vars.get(var_name)
                .cloned()
                .unwrap_or_else(|| default.to_string())
        } else {
            vars.get(expr).cloned().unwrap_or_default()
        };

        output.push_str(&rest[..start]);
        output.push_str(&value);
        rest = &rest[end + 2..];
    }

    Ok(output)
}

fn find_matching_conditional(template: &str, start: usize) -> Option<ConditionalBlock> {
    const IF_OPEN: &str = "{{#if ";
    const IF_CLOSE: &str = "{{/if}}";

    if !template[start..].starts_with(IF_OPEN) {
        return None;
    }

    let name_end_offset = template[start + IF_OPEN.len()..].find("}}")?;
    let content_start = start + IF_OPEN.len() + name_end_offset + 2;
    let mut depth = 1usize;
    let mut cursor = content_start;

    while cursor <= template.len() {
        let next_open = template[cursor..]
            .find(IF_OPEN)
            .map(|offset| cursor + offset);
        let next_close = template[cursor..]
            .find(IF_CLOSE)
            .map(|offset| cursor + offset);

        match (next_open, next_close) {
            (Some(open), Some(close)) if open < close => {
                depth += 1;
                cursor = open + IF_OPEN.len();
            }
            (_, Some(close)) => {
                depth -= 1;
                if depth == 0 {
                    return Some(ConditionalBlock {
                        start,
                        content_start,
                        end_start: close,
                    });
                }
                cursor = close + IF_CLOSE.len();
            }
            _ => return None,
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_basic_substitution() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "NetTrap".to_string());
        assert_eq!(
            render_template("Hello {{name}}", &vars).expect("render should succeed"),
            "Hello NetTrap"
        );
    }

    #[test]
    fn test_default_value() {
        let vars = HashMap::new();
        assert_eq!(
            render_template("{{name|World}}", &vars).expect("render should succeed"),
            "World"
        );
    }

    #[test]
    fn test_conditional() {
        let mut vars = HashMap::new();
        vars.insert("show".to_string(), "yes".to_string());
        assert_eq!(
            render_template("{{#if show}}visible{{/if}}", &vars).expect("render should succeed"),
            "visible"
        );

        let empty = HashMap::new();
        assert_eq!(
            render_template("{{#if show}}visible{{/if}}", &empty).expect("render should succeed"),
            ""
        );
    }

    #[test]
    fn attacker_value_cannot_inject_conditional_directives() {
        let mut vars = HashMap::new();
        vars.insert("always".to_string(), "1".to_string());
        vars.insert("host".to_string(), "A{{#if missing}}B{{/if}}C".to_string());

        let rendered =
            render_template("{{#if always}}{{host}}{{/if}}", &vars).expect("render should succeed");

        assert!(
            rendered.contains('B'),
            "injected conditional must not be evaluated, got {rendered:?}"
        );
        assert_ne!(rendered, "AC");
    }

    #[test]
    fn test_date() {
        let baseline = crate::faketime::get_delta();
        crate::faketime::set_delta(86_400);
        let vars = HashMap::new();
        let result = render_template("{{date:%Y-%m-%d}}", &vars).expect("render should succeed");
        let expected = crate::faketime::fake_now().format("%Y-%m-%d").to_string();

        assert_eq!(result, expected);
        crate::faketime::set_delta(baseline);
    }

    #[test]
    fn test_recursion_limit_returns_error() {
        let mut vars = HashMap::new();
        vars.insert("outer".to_string(), "1".to_string());
        let template = format!("{}x{}", "{{#if outer}}".repeat(17), "{{/if}}".repeat(17));

        let err = render_template(&template, &vars).expect_err("recursive template should fail");

        assert!(
            err.to_string().contains("template recursion limit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_nested_conditionals_match_correct_closing_block() {
        let mut vars = HashMap::new();
        vars.insert("outer".to_string(), "yes".to_string());
        vars.insert("inner".to_string(), "yes".to_string());

        assert_eq!(
            render_template("{{#if outer}}A{{#if inner}}B{{/if}}C{{/if}}", &vars)
                .expect("render should succeed"),
            "ABC"
        );

        vars.remove("inner");
        assert_eq!(
            render_template("{{#if outer}}A{{#if inner}}B{{/if}}C{{/if}}", &vars)
                .expect("render should succeed"),
            "AC"
        );
    }

    #[test]
    fn test_unmatched_if_block_is_left_unchanged() {
        let mut vars = HashMap::new();
        vars.insert("show".to_string(), "yes".to_string());

        assert_eq!(
            render_template("prefix {{#if show}}value", &vars).expect("render should succeed"),
            "prefix {{#if show}}value"
        );
    }

    #[test]
    fn test_substituted_value_is_not_reexpanded() {
        // Attacker-controlled values that contain template markers must be
        // emitted literally. Re-expanding them previously caused an infinite
        // loop / unbounded growth (remote DoS); these calls would hang
        // forever before the single-pass fix.
        let mut vars = HashMap::new();
        vars.insert("uri".to_string(), "{{uri}}".to_string());
        assert_eq!(
            render_template("path={{uri}}", &vars).expect("render should succeed"),
            "path={{uri}}"
        );

        vars.insert("uri".to_string(), "a{{uri}}".to_string());
        assert_eq!(
            render_template("{{uri}}", &vars).expect("render should succeed"),
            "a{{uri}}"
        );

        let mut cross = HashMap::new();
        cross.insert("host".to_string(), "{{uri}}".to_string());
        cross.insert("uri".to_string(), "{{host}}".to_string());
        assert_eq!(
            render_template("{{host}}-{{uri}}", &cross).expect("render should succeed"),
            "{{uri}}-{{host}}"
        );
    }

    #[test]
    fn unicode_whitespace_placeholder_names_do_not_match() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "NetTrap".to_string());
        vars.insert("show".to_string(), "yes".to_string());

        assert_eq!(
            render_template("{{name\u{00a0}|World}}", &vars).expect("render should succeed"),
            "World"
        );
        assert_eq!(
            render_template("{{#if show\u{00a0}}}visible{{/if}}", &vars)
                .expect("render should succeed"),
            ""
        );
    }

    #[test]
    fn ascii_whitespace_placeholder_names_do_not_match() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "NetTrap".to_string());
        vars.insert("show".to_string(), "yes".to_string());

        assert_eq!(
            render_template("{{ name }}", &vars).expect("render should succeed"),
            ""
        );
        assert_eq!(
            render_template("{{#if show }}visible{{/if}}", &vars).expect("render should succeed"),
            ""
        );
        assert_eq!(
            render_template("{{name |World}}", &vars).expect("render should succeed"),
            "World"
        );
    }
}
