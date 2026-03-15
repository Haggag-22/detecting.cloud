/**
 * In-memory event store for correlation.
 * Indexes events by eventSource, eventName, resource for fast lookup.
 */

import type { StoredEvent } from "../types";

/** Default retention: 24 hours */
const DEFAULT_RETENTION_MS = 24 * 60 * 60 * 1000;

export interface EventStoreConfig {
  retentionMs?: number;
}

export class EventStore {
  private events: StoredEvent[] = [];
  private byEventKey: Map<string, StoredEvent[]> = new Map();
  private byResource: Map<string, StoredEvent[]> = new Map();
  private retentionMs: number;

  constructor(config: EventStoreConfig = {}) {
    this.retentionMs = config.retentionMs ?? DEFAULT_RETENTION_MS;
  }

  private eventKey(source: string, name: string): string {
    return `${source}::${name}`;
  }

  private addToIndex(ev: StoredEvent): void {
    const key = this.eventKey(ev.event_source, ev.event_name);
    if (!this.byEventKey.has(key)) this.byEventKey.set(key, []);
    this.byEventKey.get(key)!.push(ev);

    if (ev.resource) {
      const rk = `${ev.event_source}:${ev.event_name}:${ev.resource}`;
      if (!this.byResource.has(rk)) this.byResource.set(rk, []);
      this.byResource.get(rk)!.push(ev);
    }
  }

  private removeFromIndex(ev: StoredEvent): void {
    const key = this.eventKey(ev.event_source, ev.event_name);
    const list = this.byEventKey.get(key);
    if (list) {
      const i = list.findIndex((e) => e.event_id === ev.event_id);
      if (i >= 0) list.splice(i, 1);
      if (list.length === 0) this.byEventKey.delete(key);
    }
    if (ev.resource) {
      const rk = `${ev.event_source}:${ev.event_name}:${ev.resource}`;
      const rlist = this.byResource.get(rk);
      if (rlist) {
        const i = rlist.findIndex((e) => e.event_id === ev.event_id);
        if (i >= 0) rlist.splice(i, 1);
        if (rlist.length === 0) this.byResource.delete(rk);
      }
    }
  }

  /** Add event and prune expired */
  add(ev: StoredEvent): void {
    this.events.push(ev);
    this.addToIndex(ev);
    this.prune();
  }

  /** Add multiple events */
  addBatch(events: StoredEvent[]): void {
    for (const ev of events) {
      this.events.push(ev);
      this.addToIndex(ev);
    }
    this.prune();
  }

  /** Remove events older than retention window */
  prune(): void {
    const cutoff = Date.now() - this.retentionMs;
    const toRemove = this.events.filter((e) => new Date(e.event_time).getTime() < cutoff);
    for (const ev of toRemove) {
      this.removeFromIndex(ev);
    }
    this.events = this.events.filter((e) => new Date(e.event_time).getTime() >= cutoff);
  }

  /** Find events by source and name */
  findByEvent(source: string, name: string): StoredEvent[] {
    const key = this.eventKey(source, name);
    const list = this.byEventKey.get(key) ?? [];
    return [...list].sort((a, b) => a.event_time.localeCompare(b.event_time));
  }

  /** Find events by source, name, and resource */
  findByEventAndResource(source: string, name: string, resource: string): StoredEvent[] {
    const rk = `${source}:${name}:${resource}`;
    const list = this.byResource.get(rk) ?? [];
    return [...list].sort((a, b) => a.event_time.localeCompare(b.event_time));
  }

  /** Find events within time window (after minTime, before maxTime) */
  findByEventInWindow(
    source: string,
    name: string,
    minTime: string,
    maxTime: string,
    resource?: string
  ): StoredEvent[] {
    const base = resource
      ? this.findByEventAndResource(source, name, resource)
      : this.findByEvent(source, name);
    return base.filter(
      (e) => e.event_time >= minTime && e.event_time <= maxTime
    );
  }

  /** Get all events (for debugging) */
  getAll(): StoredEvent[] {
    return [...this.events].sort((a, b) => a.event_time.localeCompare(b.event_time));
  }

  /** Clear store */
  clear(): void {
    this.events = [];
    this.byEventKey.clear();
    this.byResource.clear();
  }

  get size(): number {
    return this.events.length;
  }
}
