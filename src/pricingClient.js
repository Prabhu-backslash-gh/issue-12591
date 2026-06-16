// Thin client for the upstream pricing service, built on axios.
//
// >>> CVE-2026-44495 (axios < 1.15.2) <<<
// axios merges per-request config over inherited Object.prototype properties.
// If Object.prototype has been polluted (e.g. via a JSON body merged unsafely
// elsewhere in the request pipeline) with a `transformResponse` gadget, axios
// will read that inherited value off the config object below and execute it
// while processing the response — a prototype-pollution gadget chain.

const axios = require("axios");

const PRICING_BASE_URL = process.env.PRICING_BASE_URL || "https://pricing.internal.example.com";

const client = axios.create({
  baseURL: PRICING_BASE_URL,
  timeout: 5000,
  headers: { "content-type": "application/json" },
});

// Ask the pricing service to price a single line item.
async function priceLineItem(sku, quantity) {
  // The per-request config object below inherits from Object.prototype.
  // axios (< 1.15.2) mishandles an inherited `transformResponse` here.
  const resp = await client.post("/v1/price", { sku, quantity });
  return resp.data;
}

// Price every line item on an order and return the enriched totals.
async function priceOrder(order) {
  const items = order.items || [];
  const priced = await Promise.all(
    items.map((it) => priceLineItem(it.sku, it.quantity))
  );
  const total = priced.reduce((sum, p) => sum + (p.lineTotal || 0), 0);
  return { ...order, pricedItems: priced, total };
}

module.exports = { client, priceLineItem, priceOrder };
