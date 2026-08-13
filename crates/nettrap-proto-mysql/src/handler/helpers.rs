pub(crate) fn query_produces_resultset(query: &str) -> bool {
    let query =
        strip_leading_sql_comments(query.trim_start_matches(|ch: char| ch.is_ascii_whitespace()));
    let Some(verb) = query.split_ascii_whitespace().next() else {
        return false;
    };

    matches!(
        verb.to_ascii_lowercase().as_str(),
        "select"
            | "with"
            | "call"
            | "table"
            | "values"
            | "help"
            | "show"
            | "describe"
            | "desc"
            | "explain"
            | "check"
            | "analyze"
            | "optimize"
            | "repair"
    )
}

pub(crate) fn push_lenenc_str(out: &mut Vec<u8>, value: &[u8]) {
    let len = value.len();
    if len < 251 {
        out.extend_from_slice(&len.to_le_bytes()[..1]);
    } else if len < 0x1_0000 {
        out.push(0xfc);
        out.extend_from_slice(&len.to_le_bytes()[..2]);
    } else if len < 0x100_0000 {
        out.push(0xfd);
        out.extend_from_slice(&len.to_le_bytes()[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&(len as u64).to_le_bytes());
    }
    out.extend_from_slice(value);
}

fn strip_leading_sql_comments(mut query: &str) -> &str {
    loop {
        let trimmed = query.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        if trimmed.len() != query.len() {
            query = trimmed;
        }

        if let Some(rest) = query.strip_prefix("/*!") {
            let Some(end) = rest.find("*/") else {
                return query;
            };
            let inner = rest[..end]
                .trim_start_matches(|ch: char| ch.is_ascii_digit())
                .trim_start_matches(|ch: char| ch.is_ascii_whitespace());
            if inner.is_empty() {
                query = &rest[end + 2..];
            } else {
                query = inner;
            }
            continue;
        }

        if let Some(rest) = query.strip_prefix("/*") {
            let Some(end) = rest.find("*/") else {
                return query;
            };
            query = &rest[end + 2..];
            continue;
        }

        if let Some(rest) = query.strip_prefix("--")
            && (rest
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_whitespace())
                || rest.is_empty())
        {
            query = rest.trim_start_matches(|ch| ch != '\n' && ch != '\r');
            continue;
        }

        if let Some(rest) = query.strip_prefix('#') {
            query = rest.trim_start_matches(|ch| ch != '\n' && ch != '\r');
            continue;
        }

        return query;
    }
}

#[cfg(test)]
mod tests {
    use super::query_produces_resultset;

    #[test]
    fn select_query_rejects_unicode_whitespace_separators() {
        assert!(!query_produces_resultset("select\u{00a0}1"));
    }

    #[test]
    fn resultset_queries_include_information_statements() {
        assert!(query_produces_resultset("show databases"));
        assert!(query_produces_resultset("explain select 1"));
        assert!(query_produces_resultset("describe users"));
        assert!(query_produces_resultset("check table users"));
        assert!(query_produces_resultset(
            "with cte as (select 1) select * from cte"
        ));
        assert!(query_produces_resultset("call stored_proc()"));
        assert!(query_produces_resultset("table users"));
        assert!(query_produces_resultset("values row(1)"));
        assert!(query_produces_resultset("help contents"));
    }
}
