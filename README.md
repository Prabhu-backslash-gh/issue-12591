# order-ingest-service

A small but realistic Node.js microservice that ingests **protobuf-encoded orders**
over HTTP and enriches them with prices from an upstream service via **axios**.

It exists to demonstrate two real CVEs in dependencies that the app genuinely
imports and uses on its hot path — not in throwaway snippets.

| CVE                                                               | Package      | Version here | Fixed in          | Class                                        |
| ----------------------------------------------------------------- | ------------ | ------------ | ----------------- | -------------------------------------------- |
| [CVE-2026-44289](https://nvd.nist.gov/vuln/detail/CVE-2026-44289) | `protobufjs` | `7.5.5`      | `7.5.6` / `8.0.2` | CWE-674 Uncontrolled Recursion (DoS)         |
| [CVE-2026-44495](https://nvd.nist.gov/vuln/detail/CVE-2026-44495) | `axios`      | `1.15.1`     | `1.15.2`          | Prototype-pollution gadget in request config |

## Layout

```
proto/order.proto      protobuf schema (note recursive Address.forward_to)
src/orderCodec.js       protobufjs load + decode/encode  -> CVE-2026-44289 sink
src/pricingClient.js    axios pricing client             -> CVE-2026-44495 sink
src/server.js           express app wiring both together
scripts/demo.js         self-contained, offline repro of both CVEs
```

## Run

```bash
npm install

npm run demo                      # happy path: encode -> decode -> price
node scripts/demo.js --cve-44289  # protobufjs recursive-decode stack exhaustion
node scripts/demo.js --cve-44495  # axios consumes inherited transformResponse
```

You can also run the service: `npm start` then `POST /orders` with an
`application/x-protobuf` body, and `POST /orders/config` with JSON.

## How each CVE is reached

### CVE-2026-44289 — protobufjs unbounded recursive decode

`src/orderCodec.js` calls `OrderType.decode(buffer)`. protobufjs decodes nested
message fields (and skips unknown nested groups) recursively with no depth limit.
A payload with deeply nested `Address.forward_to` fields exhausts the V8 call
stack during decode (`RangeError: Maximum call stack size exceeded`) — a remote
DoS for any endpoint that decodes attacker-supplied protobuf.

### CVE-2026-44495 — axios prototype-pollution gadget

`src/pricingClient.js` issues axios requests with a per-request config object.
axios `< 1.15.2` reads option values off its schema object via the prototype
chain during request config processing, so a polluted
`Object.prototype.transformResponse` is mishandled as request configuration and
every outbound request fails. In this app the pollution source is realistic:
`POST /orders/config` recursively merges client JSON (`deepMerge`) and accepts a
`__proto__` payload, after which every `/orders` request — which calls the axios
pricing client — breaks.

## Remediation

Bump `protobufjs` to `^7.5.6` (or `^8.0.2`) and `axios` to `^1.15.2`, and never
recursively merge untrusted JSON into shared objects without a `__proto__` guard.
