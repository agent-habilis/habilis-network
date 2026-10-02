# habilis-network-netplay

GGPO-style rollback netcode for peer-to-peer games on a habilis-network mesh.

Only inputs cross the network, never game state. Each peer simulates
immediately and guesses missing remote inputs. When a real input
contradicts the guess, the session rolls back and re-simulates. Every
peer runs the same deterministic simulation, so all peers converge with
no authoritative host.

The price is strict determinism: integer arithmetic only, no floats, no
`HashMap` iteration, no clocks in the simulation. `SyncTestSession`
checks this locally instead of letting it fail as a desync mid-match.

Built for 2-8 players. Bandwidth scales with players, not world size.

See `src/lib.rs` for the API (`Config`, `Request`, `Event`) and
[`examples/light-cycles`](examples/light-cycles) for a playable game that
proves it, in a browser and a terminal.
