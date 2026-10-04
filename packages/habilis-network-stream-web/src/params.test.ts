import { expect, test } from 'bun:test'

import { DEFAULT_LOOKUP, producerParams } from './params.ts'

test('a bare page uses the lookups a tab can run, pkarr included', () => {
  const params = producerParams(new URLSearchParams(''))

  expect(params.lookup).toEqual(['relay', 'pkarr'])
  expect(params.lookup).toEqual(DEFAULT_LOOKUP)
  // Nothing a tab cannot do goes into the hash.
  expect(params.lookup).not.toContain('mdns')
  expect(params.lookup).not.toContain('dht')
  expect(params.pkarrUrls).toEqual([])
  expect(params.relayUrls).toEqual([])
  expect(params.transport).toBeUndefined()
})

test('?pkarr with urls swaps the list and keeps pkarr on', () => {
  const params = producerParams(new URLSearchParams('pkarr=https://a.example/pkarr&pkarr=https://b.example/pkarr'))

  expect(params.pkarrUrls).toEqual(['https://a.example/pkarr', 'https://b.example/pkarr'])
  expect(params.lookup).toContain('pkarr')
})

test('a bare ?pkarr is the default list, not an empty custom one', () => {
  expect(producerParams(new URLSearchParams('pkarr')).pkarrUrls).toEqual([])
})

test('relay and transport pass through', () => {
  const params = producerParams(new URLSearchParams('relay=http://127.0.0.1:1/&transport=udp,relay'))

  expect(params.relayUrls).toEqual(['http://127.0.0.1:1/'])
  expect(params.transport).toEqual(['udp', 'relay'])
})
