// Decodes binary protobuf order payloads using protobufjs.
//
// >>> CVE-2026-44289 (protobufjs < 7.5.6) <<<
// protobufjs decodes nested message fields and skips unknown group fields
// recursively with no depth limit. A crafted payload with deeply nested
// `Address.forward_to` fields (or unknown nested groups) exhausts the V8
// call stack here in `OrderType.decode(...)`, crashing the worker process.

const path = require("path");
const protobuf = require("protobufjs");

const PROTO_PATH = path.join(__dirname, "..", "proto", "order.proto");

let OrderType = null;

// Load and cache the compiled message type.
async function loadOrderType() {
  if (OrderType) return OrderType;
  const root = await protobuf.load(PROTO_PATH);
  OrderType = root.lookupType("orders.Order");
  return OrderType;
}

// Decode a Buffer of protobuf bytes into a plain order object.
async function decodeOrder(buffer) {
  const Order = await loadOrderType();
  // VULNERABLE CALL: unbounded recursive decode (CVE-2026-44289).
  const message = Order.decode(buffer);
  return Order.toObject(message, {
    longs: String,
    enums: String,
    defaults: true,
  });
}

// Encode a plain order object back into protobuf bytes (used by the demo).
async function encodeOrder(plainOrder) {
  const Order = await loadOrderType();
  const err = Order.verify(plainOrder);
  if (err) throw new Error(`invalid order: ${err}`);
  const message = Order.create(plainOrder);
  return Buffer.from(Order.encode(message).finish());
}

module.exports = { loadOrderType, decodeOrder, encodeOrder };
