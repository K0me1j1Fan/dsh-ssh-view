/**
 * Materialize the browser module without a DOM: proves that client.js parses,
 * registers its factory, exposes apply(), and registers the main page and the
 * sidebar entry through the slot API. It does not render React.
 *
 *   node test/ssh-view.client-module.mjs
 */
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))

const React = {
  createElement: (...args) => ({ type: typeof args[0] === 'string' ? args[0] : 'component', args }),
  createContext: (value) => ({ Provider: 'Provider', value }),
  useContext: () => (key) => key,
  useState: (value) => [typeof value === 'function' ? value() : value, () => {}],
  useEffect: () => {},
  useRef: (value) => ({ current: value }),
  useMemo: (fn) => fn(),
  useCallback: (fn) => fn,
  Component: class Component {
    constructor(props) {
      this.props = props
      this.state = {}
    }
    setState() {}
  },
  Fragment: 'Fragment',
}

let definition
globalThis.window = {
  __ModuleLoader__: {
    load(value) {
      definition = value
    },
  },
}
globalThis.document = { baseURI: 'http://127.0.0.1:3080/', addEventListener() {}, removeEventListener() {} }

await import(pathToFileURL(join(HERE, '..', 'client.js')).href)

assert.ok(definition, 'client module registered a factory')
assert.equal(definition.id, 'dsh-ssh-view')
assert.equal(typeof definition.factory, 'function')

const exported = definition.factory((request) => {
  assert.equal(request, 'react')
  return React
})

assert.ok(Array.isArray(exported.inject), 'declares injected services')
assert.deepEqual([...exported.inject].sort(), ['locale', 'slots'])
assert.equal(typeof exported.apply, 'function')

const slots = []
const locales = []
const ctx = {
  effect(fn) {
    return fn()
  },
  locale: {
    register(namespace, dictionaries) {
      locales.push({ namespace, dictionaries })
      return () => {}
    },
    bind() {
      return (key) => key
    },
  },
  slots: {
    inject(slot, callback) {
      callback()
    },
    register(options, component) {
      slots.push({ options, component })
      return () => {}
    },
  },
}

exported.apply(ctx)

const main = slots.find((row) => row.options.name === 'main')
const panellist = slots.find((row) => row.options.name === 'sidebar.panellist')
assert.ok(main, 'registers the main panel entry')
assert.equal(main.options.key, 'ssh-view')
assert.equal(typeof main.component, 'function')
assert.ok(panellist, 'registers the sidebar entry')
assert.equal(panellist.options.id, 'ssh-view')
assert.equal(typeof panellist.component, 'function')

assert.equal(locales.length, 1)
assert.equal(locales[0].namespace, 'ssh-view')
assert.equal(typeof locales[0].dictionaries.zh.panel, 'string')
assert.equal(typeof locales[0].dictionaries.en.panel, 'string')
assert.equal(
  Object.keys(locales[0].dictionaries.zh).length,
  Object.keys(locales[0].dictionaries.en).length,
  'both locales carry the same keys',
)

console.log('ok   client module registers main page, sidebar entry and dictionaries')
console.log(`     slots: ${slots.map((row) => row.options.name).join(', ')}`)
console.log(`     locale keys: ${Object.keys(locales[0].dictionaries.zh).length}`)
