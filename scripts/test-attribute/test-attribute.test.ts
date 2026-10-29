// Tests of scripts/test-attribute/test-attribute.ts. Each case gives a source file and the text the
// rewrite must produce. A test that keeps the attribute, or a guard in the wrong place, fails here.

import { expect, test } from "bun:test";
import { rewrite } from "./test-attribute";

const sample = `use habilis_network_test_tracing::test;

#[test]
fn sync_one() {
    assert_eq!(1 + 1, 2, "one and one make two");
}

#[test]
async fn async_one() {
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
}
`;

test("a sync test starts with the guard, and the attribute and import go", () => {
  const { text } = rewrite(sample);
  expect(text).not.toContain("use habilis_network_test_tracing::test;");
  expect(text).toContain(
    "fn sync_one() {\n    let _guard = ::habilis_network_test_tracing::init();\n    assert_eq!(1 + 1, 2, \"one and one make two\");\n}",
  );
});

test("an async test runs its body through run with the guard", () => {
  const { text } = rewrite(sample);
  expect(text).toContain("fn async_one() {");
  expect(text).not.toContain("async fn async_one");
  expect(text).toContain("::habilis_network_test_tracing::run(");
  expect(text).toContain("::habilis_network_test_tracing::init(),");
  expect(text).toContain("async {\n        tokio::time::sleep(");
});

test("other attributes stay in place, and a pub fn keeps its visibility", () => {
  const { text } = rewrite(`use habilis_network_test_tracing::test;

#[test]
#[ignore = "run by the gate row"]
pub fn ignored_one() {
    assert!(true);
}
`);
  expect(text).toContain("#[test]\n#[ignore = \"run by the gate row\"]\npub fn ignored_one() {\n    let _guard");
});

test("a multi-thread async test runs through run_multi_thread with its worker count", () => {
  const { text } = rewrite(`use habilis_network_test_tracing::test;

#[test(flavor = "multi_thread", worker_threads = 2)]
async fn multi() {
    tick().await;
}
`);
  expect(text).toContain("::habilis_network_test_tracing::run_multi_thread(::habilis_network_test_tracing::init(), 2, async {");
});

test("braces in strings, raw strings and char literals do not end the body early", () => {
  const { text, flagged } = rewrite(`use habilis_network_test_tracing::test;

#[test]
fn tricky() {
    let a = "}";
    let b = r#"}"#;
    let c = '}';
    assert!(a.len() + b.len() + usize::from(c == '}') > 0); // }
}
`);
  expect(flagged).toEqual([]);
  expect(text).toContain("    let _guard = ::habilis_network_test_tracing::init();\n    let a = \"}\";");
  expect(text.trimEnd().endsWith("// }\n}")).toBe(true);
});

test("a test with arguments this does not handle is flagged and not rewritten", () => {
  const { flagged } = rewrite(`use habilis_network_test_tracing::test;

#[test(flavor = "multi_thread")]
async fn no_workers() {}
`);
  expect(flagged.length).toBeGreaterThan(0);
});

test("a brace import keeps its other items and drops test", () => {
  const { text } = rewrite(`use habilis_network_test_tracing::{expect_warn, test};

#[test]
fn one() {
    expect_warn("t", "x");
}
`);
  expect(text).not.toContain("use habilis_network_test_tracing::expect_warn");
  expect(text).toContain("::habilis_network_test_tracing::expect_warn(\"t\", \"x\");");
});

test("a brace import of test alone is removed", () => {
  const { text } = rewrite(`use habilis_network_test_tracing::{at_end, test};

#[test]
fn one() {}
`);
  expect(text).not.toContain("use habilis_network_test_tracing::at_end");
});

test("a proptest case with parameters gets the guard and keeps its parameters", () => {
  const { text, flagged } = rewrite(`use habilis_network_test_tracing::test;

proptest! {
    #[test]
    fn prop_one(seed in arb_seed(), name in arb_name()) {
        assert!(seed.len() > 0 && name.len() > 0);
    }
}
`);
  expect(flagged).toEqual([]);
  expect(text).toContain("fn prop_one(seed in arb_seed(), name in arb_name()) {\n        let _guard = ::habilis_network_test_tracing::init();\n        assert!(");
});

test("every plain import of the attribute is removed, not only the first", () => {
  const { text } = rewrite(`mod a {
    use habilis_network_test_tracing::test;

    #[test]
    fn one() {}
}

mod b {
    use habilis_network_test_tracing::test;

    #[test]
    fn two() {}
}
`);
  expect(text).not.toContain("use habilis_network_test_tracing::test;");
});

test("the guard goes after the items that open a sync test body", () => {
  const { text } = rewrite(`use habilis_network_test_tracing::test;

#[test]
fn opens_with_items() {
    use std::collections::HashSet;
    const N: usize = 2;
    let set: HashSet<usize> = HashSet::new();
    assert!(set.is_empty() && N > 0);
}
`);
  expect(text).toContain("    const N: usize = 2;\n    let _guard = ::habilis_network_test_tracing::init();\n    let set");
});

test("an attribute that spans lines stays in place", () => {
  const { text, flagged } = rewrite(`use habilis_network_test_tracing::test;

#[test]
#[expect(
    unsafe_code,
    reason = "libc mmap and munmap"
)]
fn spans_lines() {
    assert!(true);
}
`);
  expect(flagged).toEqual([]);
  expect(text).toContain("#[test]\n#[expect(\n    unsafe_code,\n    reason = \"libc mmap and munmap\"\n)]\nfn spans_lines() {\n    let _guard");
});

test("a file that does not import the attribute is left alone", () => {
  const source = `#[test]
fn std_test() {
    let guard = habilis_network_test_tracing::init();
    habilis_network_test_tracing::run(guard, async {});
}
`;
  const { text, flagged } = rewrite(source);
  expect(flagged).toEqual([]);
  expect(text).toBe(source);
});

test("a comment before the leading items does not stop the guard from going after them", () => {
  const { text } = rewrite(`use habilis_network_test_tracing::test;

#[test]
fn commented() {
    // why the items come first
    use std::collections::HashSet;
    let set: HashSet<usize> = HashSet::new();
    assert!(set.is_empty());
}
`);
  expect(text).toContain("    // why the items come first\n    use std::collections::HashSet;\n    let _guard = ::habilis_network_test_tracing::init();\n    let set");
});
