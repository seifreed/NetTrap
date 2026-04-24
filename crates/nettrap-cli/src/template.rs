//! Simple template engine for response customization.
//! Supports variable substitution, conditionals, and date formatting.
//!
//! Variables: {{variable_name}}
//! Date: {{date}} {{date:%Y-%m-%d}} {{date:%a, %d %b %Y %H:%M:%S GMT}}
//! Conditionals: {{#if variable}}content{{/if}}
//! Defaults: {{variable|default_value}}

pub fn render_template(template: &str, vars: &std::collections::HashMap<String, String>) -> String {
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
) -> String {
    const MAX_DEPTH: usize = 16;
    if depth >= MAX_DEPTH {
        tracing::warn!("Template recursion limit ({}) reached, stopping", MAX_DEPTH);
        return template.to_string();
    }

    // Process escape sequences BEFORE variable substitution to prevent
    // attacker-controlled values from injecting control characters
    let mut result = template
        .replace("\\r\\n", "\r\n")
        .replace("\\n", "\n")
        .replace("\\t", "\t");

    // Process conditionals first: {{#if var}}content{{/if}}
    loop {
        let Some(start) = result.find("{{#if ") else {
            break;
        };

        let Some(name_end_offset) = result[start + 6..].find("}}") else {
            break;
        };
        let name_end = start + 6 + name_end_offset;

        let var_name = result[start + 6..name_end].trim();
        let Some(block) = find_matching_conditional(&result, start) else {
            break;
        };

        let content = &result[block.content_start..block.end_start];
        let var_exists = vars.get(var_name).map(|v| !v.is_empty()).unwrap_or(false);

        if var_exists {
            let rendered = render_template_depth(content, vars, depth + 1);
            result = format!(
                "{}{}{}",
                &result[..block.start],
                rendered,
                &result[block.end_start + 7..]
            );
        } else {
            result = format!(
                "{}{}",
                &result[..block.start],
                &result[block.end_start + 7..]
            );
        }
    }

    // Process variables with defaults: {{var|default}}
    loop {
        let Some(start) = result.find("{{") else {
            break;
        };

        // Leave malformed control markers untouched rather than stripping them.
        if result[start..].starts_with("{{#") || result[start..].starts_with("{{/") {
            break;
        }

        let Some(end_offset) = result[start + 2..].find("}}") else {
            break;
        };
        let end = start + 2 + end_offset;

        let expr = result[start + 2..end].trim();

        let value = if expr == "date" || expr.starts_with("date:") {
            let fmt = expr.strip_prefix("date:").unwrap_or("%Y-%m-%d %H:%M:%S");
            // Validate format string by attempting to format; fall back on invalid specifiers
            let formatted = std::panic::catch_unwind(|| chrono::Utc::now().format(fmt).to_string());
            match formatted {
                Ok(s) => s,
                Err(_) => {
                    tracing::warn!("Invalid date format '{}' in template, using default", fmt);
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
                }
            }
        } else if expr.contains('|') {
            let parts: Vec<&str> = expr.splitn(2, '|').collect();
            let var_name = parts[0].trim();
            let default = parts[1].trim();
            vars.get(var_name)
                .cloned()
                .unwrap_or_else(|| default.to_string())
        } else {
            vars.get(expr).cloned().unwrap_or_default()
        };

        result = format!("{}{}{}", &result[..start], value, &result[end + 2..]);
    }

    result
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
        assert_eq!(render_template("Hello {{name}}", &vars), "Hello NetTrap");
    }

    #[test]
    fn test_default_value() {
        let vars = HashMap::new();
        assert_eq!(render_template("{{name|World}}", &vars), "World");
    }

    #[test]
    fn test_conditional() {
        let mut vars = HashMap::new();
        vars.insert("show".to_string(), "yes".to_string());
        assert_eq!(
            render_template("{{#if show}}visible{{/if}}", &vars),
            "visible"
        );

        let empty = HashMap::new();
        assert_eq!(render_template("{{#if show}}visible{{/if}}", &empty), "");
    }

    #[test]
    fn test_date() {
        let vars = HashMap::new();
        let result = render_template("{{date:%Y}}", &vars);
        assert!(result.len() == 4); // Year is 4 digits
    }

    #[test]
    fn test_nested_conditionals_match_correct_closing_block() {
        let mut vars = HashMap::new();
        vars.insert("outer".to_string(), "yes".to_string());
        vars.insert("inner".to_string(), "yes".to_string());

        assert_eq!(
            render_template("{{#if outer}}A{{#if inner}}B{{/if}}C{{/if}}", &vars),
            "ABC"
        );

        vars.remove("inner");
        assert_eq!(
            render_template("{{#if outer}}A{{#if inner}}B{{/if}}C{{/if}}", &vars),
            "AC"
        );
    }

    #[test]
    fn test_unmatched_if_block_is_left_unchanged() {
        let mut vars = HashMap::new();
        vars.insert("show".to_string(), "yes".to_string());

        assert_eq!(
            render_template("prefix {{#if show}}value", &vars),
            "prefix {{#if show}}value"
        );
    }
}
