"use strict";
const https = require("node:https"), fs = require("node:fs"), crypto = require("node:crypto");
function api(resource, key, { file, size, signal } = {}) {
  return new Promise((resolve, reject) => {
    const boundary = "DropSync" + crypto.randomBytes(16).toString("hex");
    const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="sample.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`);
    const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
    const headers = { "x-apikey": key, Accept: "application/json", "User-Agent": "DropSync" };
    if (file) Object.assign(headers, { "Content-Type": `multipart/form-data; boundary=${boundary}`, "Content-Length": head.length + size + tail.length });
    const request = https.request({ hostname: "www.virustotal.com", port: 443, path: `/api/v3/${resource}`, method: file ? "POST" : "GET", headers, timeout: 20000, signal }, (response) => {
      if (response.statusCode === 404) { response.resume(); return resolve(null); }
      if (response.statusCode !== 200) { response.resume(); return reject(new Error(response.statusCode === 429 ? "VirusTotal quota exceeded; retry later" : `VirusTotal request failed (${response.statusCode})`)); }
      let size = 0; const chunks = []; response.on("data", (chunk) => { size += chunk.length; if (size > 262144) response.destroy(new Error("Scan response exceeded limits")); else chunks.push(chunk); });
      response.on("error", reject); response.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch { reject(new Error("Invalid VirusTotal response")); } });
    });
    request.on("timeout", () => request.destroy(new Error("VirusTotal request timed out"))); request.on("error", reject);
    if (!file) request.end();
    else { request.write(head); const source = fs.createReadStream(file); source.on("error", (error) => request.destroy(error)); request.on("close", () => source.destroy()); source.pipe(request, { end: false }); source.on("end", () => request.end(tail)); }
  });
}
function verdict(stats) {
  if (!stats || !["malicious", "suspicious", "undetected", "harmless"].every((key) => Number.isInteger(stats[key]) && stats[key] >= 0)) throw new Error("Invalid VirusTotal report");
  if (stats.malicious || stats.suspicious) return "malicious";
  return stats.undetected + stats.harmless ? "no-detections" : "unknown";
}
class ThreatScanner {
  constructor(store) { this.store = store; this.cache = new Map(); this.queue = Promise.resolve(); this.nextRequest = 0; this.inFlight = new Set(); }
  invalidate() { this.cache.clear(); for (const controller of this.inFlight) controller.abort(new Error("VirusTotal configuration changed; retry the transfer")); }
  request(resource, key, options = {}) {
    const work = this.queue.then(async () => {
      options.signal?.throwIfAborted(); const wait = Math.max(0, this.nextRequest - Date.now());
      if (wait) await require("node:timers/promises").setTimeout(wait, undefined, { signal: options.signal });
      options.signal?.throwIfAborted();
      if (!this.store.settings.virusTotalEnabled || this.store.getSecret("virusTotalApiKey") !== key || (options.file && !this.store.settings.virusTotalUploadUnknown)) throw new Error("VirusTotal permission or API key changed; retry the transfer");
      this.nextRequest = Date.now() + 16000; return api(resource, key, options);
    });
    this.queue = work.catch(() => {}); return work;
  }
  async lookup(hash, key, signal) {
    const prior = this.cache.get(hash); if (prior && Date.now() - prior.time < 600000) return prior.result;
    if (this.cache.size >= 256) this.cache.delete(this.cache.keys().next().value);
    const result = this.request(`files/${hash}`, key, { signal }).then((report) => report ? verdict(report.data?.attributes?.last_analysis_stats) : "unknown");
    this.cache.set(hash, { time: Date.now(), result });
    try { return await result; } catch (error) { this.cache.delete(hash); throw error; }
  }
  async inspect(hash, file = null, { signal } = {}) {
    const settings = this.store.settings; if (!settings.virusTotalEnabled) return "not-scanned";
    if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error("Invalid scan digest");
    const key = this.store.getSecret("virusTotalApiKey"); if (!key) throw new Error("Configure your VirusTotal API key before enabling checks");
    const controller = new AbortController(); this.inFlight.add(controller);
    try {
    const timeout = AbortSignal.timeout(150000); signal = AbortSignal.any([...(signal ? [signal] : []), timeout, controller.signal]);
    let status = await this.lookup(hash, key, signal);
    if (status === "malicious") throw new Error("VirusTotal detected this file; transfer blocked");
    if (status === "unknown" && settings.virusTotalUploadUnknown && file) {
      const size = fs.statSync(file).size; if (size > 32 * 1024 * 1024) throw new Error("VirusTotal content uploads are limited to 32 MiB");
      const response = await this.request("files", key, { file, size, signal }), id = response?.data?.id;
      if (typeof id !== "string" || !/^[a-zA-Z0-9_+=:-]{1,300}$/.test(id)) throw new Error("Invalid VirusTotal analysis reference");
      for (let attempt = 0; attempt < 6; attempt++) {
        await new Promise((resolve, reject) => { const timer = setTimeout(done, 15000); function done() { signal.removeEventListener("abort", abort); resolve(); } function abort() { clearTimeout(timer); reject(new Error("Scan cancelled")); } signal.addEventListener("abort", abort, { once: true }); if (signal.aborted) abort(); });
        const report = await this.request(`analyses/${encodeURIComponent(id)}`, key, { signal });
        if (report?.data?.attributes?.status === "completed") { status = verdict(report.data.attributes.stats); break; }
      }
      this.cache.set(hash, { time: Date.now(), result: Promise.resolve(status) });
      if (status === "malicious") throw new Error("VirusTotal detected this file; transfer blocked");
    }
    if (status === "unknown" && settings.virusTotalBlockUnknown) {
      if (!file && settings.virusTotalUploadUnknown) return "analysis-required";
      throw new Error("VirusTotal has no completed report; blocked by your unknown-file policy");
    }
    return status === "no-detections" ? "virustotal-no-detections" : "virustotal-unknown";
    } finally { this.inFlight.delete(controller); }
  }
}
module.exports = { ThreatScanner, verdict };
