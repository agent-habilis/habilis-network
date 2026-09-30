import { expect, test } from 'bun:test'
import { parseChatArgs } from './args.ts'

test('a create takes pkarr relays, repeatable', () => {
  const { entry } = parseChatArgs([
    '--create',
    '--lookup',
    'relay,pkarr',
    '--pkarr-url',
    'https://a.example/pkarr',
    '--pkarr-url',
    'https://b.example/pkarr',
  ])
  expect(entry).toEqual({
    kind: 'create',
    opts: { lookup: ['relay', 'pkarr'], pkarrUrls: ['https://a.example/pkarr', 'https://b.example/pkarr'] },
  })
})

test('a topic or an id refuses pkarr relays', () => {
  expect(() => parseChatArgs(['--topic', 't', '--pkarr-url', 'https://a.example/pkarr'])).toThrow('--create')
  expect(() => parseChatArgs(['--id', 'm', '--pkarr-url', 'https://a.example/pkarr'])).toThrow('--create')
})
