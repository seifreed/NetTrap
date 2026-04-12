/// Simple template engine for response customization.
/// Supports variable substitution, conditionals, and date formatting.
///
/// Variables: {{variable_name}}
/// Date: {{date}} {{date:%Y-%m-%d}} {{date:%a, %d %b %Y %H:%M:%S GMT}}
/// Conditionals: {{#if variable}}content{{/if}}
/// Defaults: {{variable|default_value}}

pub fn render_template(template: &str, vars: &std::collections::HashMap<String, String>) -> String {
    render_template_depth(template, vars, 0)
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
        let Some(endif_offset) = result[name_end + 2..].find("{{/if}}") else {
            break;
        };
        let endif = name_end + 2 + endif_offset;

        let content = &result[name_end + 2..endif];
        let var_exists = vars.get(var_name).map(|v| !v.is_empty()).unwrap_or(false);

        if var_exists {
            let rendered = render_template_depth(content, vars, depth + 1);
            result = format!("{}{}{}", &result[..start], rendered, &result[endif + 7..]);
        } else {
            result = format!("{}{}", &result[..start], &result[endif + 7..]);
        }
    }

    // Process variables with defaults: {{var|default}}
    loop {
        let Some(start) = result.find("{{") else {
            break;
        };

        // Skip conditionals
        if result[start..].starts_with("{{#") || result[start..].starts_with("{{/") {
            break;
        }

        let Some(end_offset) = result[start + 2..].find("}}") else {
            break;
        };
        let end = start + 2 + end_offset;

        let expr = result[start + 2..end].trim();

        let value = if expr == "date" || expr.starts_with("date:") {
            let fmt = if expr.starts_with("date:") {
                &expr[5..]
            } else {
                "%Y-%m-%d %H:%M:%S"
            };
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
}
