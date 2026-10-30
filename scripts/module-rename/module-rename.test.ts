import { describe, expect, test } from "bun:test";
import { renameInText } from "./module-rename";

const o = { crate: "habilis-network-protocol", from: "mesh", to: "meshes" };
const protocolLib = "crates/habilis-network-protocol/src/lib.rs";
const meshDirFile = "crates/habilis-network-protocol/src/mesh/mod.rs";
const otherFile = "crates/habilis-network-protocol/src/resolver/mod.rs";
const engineFile = "crates/habilis-network/src/daemon/setup.rs";

describe("renameInText", () => {
  test("rewrites the re-exported path in other crates", () => {
    expect(renameInText("use habilis_network::protocol::mesh::Mesh;", engineFile, o)).toBe(
      "use habilis_network::protocol::meshes::Mesh;",
    );
  });

  test("rewrites the crate's own name", () => {
    expect(renameInText("habilis_network_protocol::mesh::Mesh", engineFile, o)).toBe(
      "habilis_network_protocol::meshes::Mesh",
    );
  });

  test("leaves a different module of the same name in another crate", () => {
    expect(renameInText("use crate::mesh::Mesh;", engineFile, o)).toBe("use crate::mesh::Mesh;");
  });

  test("rewrites the module declaration and the crate-relative paths in the crate", () => {
    expect(renameInText("pub mod mesh;\nuse crate::mesh::Mesh;", protocolLib, o)).toBe(
      "pub mod meshes;\nuse crate::meshes::Mesh;",
    );
  });

  test("rewrites a bare path from a file outside the module's directory", () => {
    expect(renameInText("fn f() -> mesh::Mesh {", otherFile, o)).toBe("fn f() -> meshes::Mesh {");
  });

  test("keeps the child module path inside the module's own directory", () => {
    expect(renameInText("pub use mesh::Mesh;", meshDirFile, o)).toBe("pub use mesh::Mesh;");
  });

  test("rewrites a path written as a file in docs", () => {
    expect(renameInText("see crates/habilis-network-protocol/src/mesh/mod.rs", "AGENTS.md", o)).toBe(
      "see crates/habilis-network-protocol/src/meshes/mod.rs",
    );
  });

  test("does not touch a longer identifier", () => {
    expect(renameInText("let meshes = mesh_id::value;", otherFile, o)).toBe("let meshes = mesh_id::value;");
  });
});

describe("renameInText, use groups and inception", () => {
  test("renames the module named inside a use group", () => {
    expect(renameInText("use crate::{crypto, invite, mesh};", otherFile, o)).toBe(
      "use crate::{crypto, invite, meshes};",
    );
  });

  test("drops the module_inception expect from the module's own mod.rs", () => {
    const text = "#[expect(\n    clippy::module_inception,\n    reason = \"the file is named for its type\"\n)]\nmod mesh;\n";
    expect(renameInText(text, meshDirFile, o)).toBe("mod mesh;\n");
  });
});

describe("renameInText, the crate's own use groups", () => {
  test("renames the module inside a re-export group of the crate", () => {
    expect(renameInText("pub use habilis_network_protocol::{identity, mesh, message};", engineFile, o)).toBe(
      "pub use habilis_network_protocol::{identity, meshes, message};",
    );
  });
});

describe("renameInText, a file that imports the module by name", () => {
  test("renames its bare module paths", () => {
    const text = "use crate::protocol::meshes;\nfn f() -> mesh::Mesh { mesh::Mesh::try_new() }";
    expect(renameInText(text, "crates/habilis-network/src/blob/ticket.rs", o)).toBe(
      "use crate::protocol::meshes;\nfn f() -> meshes::Mesh { meshes::Mesh::try_new() }",
    );
  });
});
