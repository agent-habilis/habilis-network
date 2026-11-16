import { expect, test } from 'bun:test'

import { parseChatArgs } from './args.ts'

test('a --nostr-url that holds a comma is refused, not split into two relays', () => {
  expect(() => parseChatArgs(['--topic', 'room', '--nostr-url', 'wss://relay.example/a,b'])).toThrow(
    '--nostr-url',
  )
})

test('repeated --nostr-url values pass through as given', () => {
  const { entry } = parseChatArgs([
    '--topic',
    'room',
    '--nostr-url',
    'wss://a.example/',
    '--nostr-url',
    'wss://b.example/',
  ])
  expect(entry.kind === 'join' && 'nostrUrls' in entry.opts ? entry.opts.nostrUrls : undefined).toEqual([
    'wss://a.example/',
    'wss://b.example/',
  ])
})

test('a --relay-url that holds a comma is refused, not split into two relays', () => {
  expect(() => parseChatArgs(['--topic', 'room', '--relay-url', 'https://relay.example/a,b'])).toThrow(
    '--relay-url',
  )
})
