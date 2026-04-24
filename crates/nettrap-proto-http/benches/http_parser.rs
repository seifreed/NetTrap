use criterion::{Criterion, criterion_group, criterion_main};
use nettrap_proto_http::HttpRequestParsed;
use std::hint::black_box;

fn bench_http_request_parser(c: &mut Criterion) {
    let get = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: NetTrapBench\r\n\r\n";
    let post =
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 11\r\n\r\nhello world";
    let chunked = b"POST /stream HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

    c.bench_function("http_parse_get", |b| {
        b.iter(|| HttpRequestParsed::parse(black_box(get)))
    });
    c.bench_function("http_parse_post_content_length", |b| {
        b.iter(|| HttpRequestParsed::parse(black_box(post)))
    });
    c.bench_function("http_parse_chunked", |b| {
        b.iter(|| HttpRequestParsed::parse(black_box(chunked)))
    });
}

criterion_group!(benches, bench_http_request_parser);
criterion_main!(benches);
