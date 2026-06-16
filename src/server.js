// Order ingestion HTTP service.
//
// POST /orders        - raw protobuf body (application/x-protobuf), decoded
//                       with protobufjs then priced via the axios pricing client.
// POST /orders/config - JSON body recursively merged into per-request defaults
//                       (the realistic source of a prototype-pollution gadget).

const express = require("express");
const { decodeOrder } = require("./orderCodec");
const { priceOrder } = require("./pricingClient");

const app = express();

app.use(express.json());
app.use(express.raw({ type: "application/x-protobuf", limit: "1mb" }));

// Naive recursive merge — the typical real-world prototype-pollution source
// that feeds the axios gadget in CVE-2026-44495.
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === "object") {
      target[key] = target[key] || {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

const requestDefaults = {};

// Accepts a protobuf-encoded order, decodes it, and enriches it with pricing.
app.post("/orders", async (req, res) => {
  try {
    const order = await decodeOrder(req.body); // CVE-2026-44289 entry point
    const priced = await priceOrder(order);    // CVE-2026-44495 entry point
    res.json(priced);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Lets clients tweak request defaults; unsafe merge enables prototype pollution.
app.post("/orders/config", (req, res) => {
  deepMerge(requestDefaults, req.body || {});
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`order-ingest-service on :${PORT}`));
}

module.exports = app;
