"use strict";
const { setTimeout: delay } = require("node:timers/promises");
class BandwidthLimiter {
  constructor(rate) { this.rate = rate; this.tokens = 0; this.last = performance.now(); }
  async consume(bytes, checkpoint = () => {}) {
    let remaining = bytes;
    while (remaining > 0) {
      checkpoint(); const rate = Number(this.rate()); if (!Number.isFinite(rate) || rate <= 0) return;
      const now = performance.now(), cap = Math.max(256, rate / 4);
      this.tokens = Math.min(cap, this.tokens + (now - this.last) * rate / 1000); this.last = now;
      const used = Math.min(remaining, Math.floor(this.tokens)); this.tokens -= used; remaining -= used;
      if (remaining > 0) await delay(Math.min(100, Math.max(1, (Math.min(remaining, cap) - this.tokens) * 1000 / rate)));
    }
  }
}
module.exports = { BandwidthLimiter };
