# The tail example: a growing file, streamed

`tail -f` into `fofoca-stream`: one reader, in a terminal or a browser tab,
gets the last lines of a file and then every line appended to it. The bytes go
over a direct path from this machine to the reader by default, and never
through gossip.

A stream has one reader. The first reader to open the hash gets the stream,
and a second one is refused. To give a file to two readers, run the script
twice and hand out two hashes.

## Run it

```sh
cargo build -p fofoca-stream-cli                   # the fofoca-stream binary
export FOFOCA_STREAM=$PWD/target/debug/fofoca-stream
examples/tail/tail.sh app.log
```

The script prints a hash on stderr and waits for the reader. Read the stream
in a second terminal:

```sh
fofoca-stream <hash>
```

Or read it in a browser. Serve the stream page, then give the script its URL:

```sh
cargo task build-wasm                              # once
bun run --cwd packages/fofoca-stream-web serve     # 3020, or the next free port
examples/tail/tail.sh app.log --web-url http://127.0.0.1:3020/
```

The script prints `open http://127.0.0.1:3020/#<hash>`. Open that URL.

Append to the file (`echo hello >> app.log`) and the line reaches the reader.

There are two ways to stop:

- Ctrl-C reaches `fofoca-stream` too, so the reader usually gets an error:
  "the producer abandoned the stream".
- `kill <pid of tail.sh>` stops `tail` only. The input ends, and the reader
  gets the end of the stream. With no reader attached yet, the script stops
  `fofoca-stream` too after 10 s, and exits 143.

## Tested

`cargo task e2e --suite stream` runs this shape: the input grows after the
page attaches, and both lines arrive in order, then the end.
