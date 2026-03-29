/// Simple template engine for response customization.
/// Supports variable substitution, conditionals, and date formatting.
///
/// Variables: {{variable_name}}
/// Date: {{date}} {{date:%Y-%m-%d}} {{date:%a, %d %b %Y %H:%M:%S GMT}}
/// Conditionals: {{#if variable}}content{{/if}}
/// Defaults: {{variable|default_value}}

pub fn render_template(template: &str, vars: &std::collections::HashMap<String, String>) -> String {
    let mut result = template.to_string();

    // Process conditionals first: {{#if var}}content{{/if}}
    loop {
        let start = result.find("{{#if ");
        if start.is_none() {
            break;
        }
        let start = start.unwrap();

        let name_end = result[start + 6..].find("}}");
        if name_end.is_none() {
            break;
        }
        let name_end = start + 6 + name_end.unwrap();

        let var_name = result[start + 6..name_end].trim();
        let endif = result[name_end + 2..].find("{{/if}}");
        if endif.is_none() {
            break;
        }
        let endif = name_end + 2 + endif.unwrap();

        let content = &result[name_end + 2..endif];
        let var_exists = vars
            .get(var_name)
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        if var_exists {
            let rendered = render_template(content, vars);
            result = format!("{}{}{}", &result[..start], rendered, &result[endif + 7..]);
        } else {
            result = format!("{}{}", &result[..start], &result[endif + 7..]);
        }
    }

    // Process variables with defaults: {{var|default}}
    loop {
        let start = result.find("{{");
        if start.is_none() {
            break;
        }
        let start = start.unwrap();

        // Skip conditionals
        if result[start..].starts_with("{{#") || result[start..].starts_with("{{/") {
            break;
        }

        let end = result[start + 2..].find("}}");
        if end.is_none() {
            break;
        }
        let end = start + 2 + end.unwrap();

        let expr = result[start + 2..end].trim();

        let value = if expr == "date" || expr.starts_with("date:") {
            let fmt = if expr.starts_with("date:") {
                &expr[5..]
            } else {
                "%Y-%m-%d %H:%M:%S"
            };
            chrono::Utc::now().format(fmt).to_string()
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

    // Process escape sequences
    result = result.replace("\\r\\n", "\r\n");
    result = result.replace("\\n", "\n");
    result = result.replace("\\t", "\t");

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
        assert_eq!(
            render_template("{{#if show}}visible{{/if}}", &empty),
            ""
        );
    }

    #[test]
    fn test_date() {
        let vars = HashMap::new();
        let result = render_template("{{date:%Y}}", &vars);
        assert!(result.len() == 4); // Year is 4 digits
    }
}
