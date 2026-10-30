"use strict";
const { canonicalJson, safeFileName } = require("./utils");

const APPROVAL_TTL_MS = 90_000;

class IncomingApprovals {
  constructor({ store, onChange }) {
    this.store = store;
    this.onChange = onChange;
    this.requests = new Map();
  }

  list() {
    return [...this.requests.values()].filter((item) => item.status === "pending").map((item) => ({
      id: item.meta.transferId, deviceId: item.meta.senderId, deviceName: item.deviceName, deviceType: item.deviceType, fileName: safeFileName(item.meta.fileName),
      size: item.meta.size, expiresAt: item.expiresAt,
    }));
  }

  ensure(meta, trusted, authorized = false) {
    const previous = this.requests.get(meta.transferId);
    if (previous) {
      if (previous.canonical !== canonicalJson(meta)) throw new Error("Transfer metadata changed after requesting approval");
      return previous;
    }
    if (authorized || this.store.settings.requireIncomingApproval === false) return { status: "accepted", meta };
    if (this.list().length >= 20) throw new Error("Too many incoming requests. Try again later");
    for (const [id, item] of this.requests) if (item.expiresAt + 10 * 60_000 < Date.now()) this.requests.delete(id);
    if (this.requests.size >= 500) throw new Error("Too many recent incoming requests");
    const item = { meta, canonical: canonicalJson(meta), deviceName: trusted.name, deviceType: trusted.deviceType, status: "pending",
      expiresAt: Date.now() + APPROVAL_TTL_MS, waiters: new Set() };
    item.timer = setTimeout(() => this.settle(item, "expired"), APPROVAL_TTL_MS);
    item.timer.unref?.();
    this.requests.set(meta.transferId, item);
    this.record(item, "awaiting-approval");
    this.onChange?.(this.list());
    return item;
  }

  record(item, status, error = null) {
    this.store.addTransfer({ id: item.meta.transferId, direction: "receive", deviceId: item.meta.senderId,
      deviceName: item.deviceName, fileName: safeFileName(item.meta.fileName), size: item.meta.size,
      sha256: item.meta.sha256, bytesTransferred: 0, progress: 0, status, encrypted: true, error,
      createdAt: new Date(item.expiresAt - APPROVAL_TTL_MS).toISOString(), updatedAt: new Date().toISOString() });
  }

  settle(item, status) {
    if (item.status !== "pending" && !(item.status === "accepted" && status === "rejected")) return;
    clearTimeout(item.timer);
    item.status = status;
    this.record(item, status === "accepted" ? "waiting-for-sender" : "rejected",
      status === "accepted" ? null : status === "expired" ? "Incoming request expired" : "Incoming transfer declined");
    for (const resolve of item.waiters) resolve(status);
    item.waiters.clear();
    this.onChange?.(this.list());
    if (status === "accepted") {
      item.timer = setTimeout(() => {
        if (item.status !== "accepted") return;
        item.status = "expired"; this.record(item, "rejected", "Sender did not start the transfer after acceptance"); this.onChange?.(this.list());
      }, 45_000);
      item.timer.unref?.();
    }
  }

  decide(id, accept) {
    const item = this.requests.get(id);
    if (!item || (item.status !== "pending" && !(item.status === "accepted" && !accept))) throw new Error("This incoming request is no longer pending");
    this.settle(item, accept ? "accepted" : "rejected");
  }

  async wait(item, request) {
    if (item.status !== "pending") return item.status;
    return new Promise((resolve) => {
      const done = (status) => { item.waiters.delete(done); request.off("aborted", aborted); resolve(status); };
      const aborted = () => { this.settle(item, "rejected"); done("rejected"); };
      item.waiters.add(done);
      request.once("aborted", aborted);
      if (request.aborted) aborted();
    });
  }

  finish(id) {
    const item = this.requests.get(id);
    if (item) clearTimeout(item.timer);
    this.requests.delete(id);
  }
}

module.exports = { IncomingApprovals, APPROVAL_TTL_MS };
