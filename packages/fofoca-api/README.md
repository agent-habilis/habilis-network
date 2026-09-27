# fofoca-api

The TypeScript mesh API: the types both backends implement, and the
machinery they share.

This package is the contract, not a way to join a mesh. A backend package
re-exports everything here and adds `join` / `create`.

- Types: `Mesh`, `Peer`, `Message`, `MeshEvent`, `StateDoc`, `Lane`,
  `Reach`.
- Values: `openMesh`, `randomNick`, `randomTopic`, `Fanout`.
- The backend seam: `MeshBackend`, `BackendMsg`, `BackendSink`,
  `Opener`. A consumer never needs these; a third backend would.

See [`../README.md`](../README.md) for the workspace rules, and
`src/index.ts` for the full export list.
