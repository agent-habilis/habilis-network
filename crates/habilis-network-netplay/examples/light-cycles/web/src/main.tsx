import { render } from 'visage-dom'

import { App } from './App.tsx'
import { loadWasm } from './wasm.ts'

// Start the wasm fetch+compile now rather than when the player clicks
// "join" — it's the largest asset on the page, and the promise memo in
// `wasm.ts` makes the later real call free.
void loadWasm()

const root = document.getElementById('root')
if (!root) throw new Error('#root is missing from index.html')

render(App(), root)
