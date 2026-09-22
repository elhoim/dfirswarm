/**
 * SSE connection + stale-while-revalidate resources.
 *
 * One EventSource per tab. Every `change` bumps a version for the swarms it
 * names, and one per kind of thing that moved under each; a change that
 * names no swarm, or that touched the registry, bumps the registry version;
 * and the fleet-wide version moves on either. A swarm's page is keyed on its
 * own version plus the registry's, a panel on the kinds it reads, so another
 * swarm's traffic, or a claim landing while you read the trace, does not
 * refetch what did not change. Nothing here ticks on a timer: the clocks
 * that have to keep moving use `useNow`, which re-renders without refetching.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { ChangeEvent, ChangeKind, Job } from "./types";

export type LiveStatus = "connecting" | "live" | "offline";

type LiveState = {
  status: LiveStatus;
  /** Moves on every change anywhere: the overview's key. */
  globalVersion: number;
  /** Moves when the registry changed, or a change named no swarm: part of every swarm page's key. */
  registryVersion: number;
  /** Any kind, per swarm. */
  swarmVersions: Record<string, number>;
  /** Per swarm, per kind. */
  swarmKindVersions: Record<string, Record<string, number>>;
  jobs: Record<string, Job>;
  lastChange: ChangeEvent | null;
  watching: boolean;
};

type LiveValue = LiveState & { mergeJobs: (jobs: Job[]) => void };

const LiveContext = createContext<LiveValue | null>(null);

export function LiveProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<LiveState>({
    status: "connecting",
    globalVersion: 0,
    registryVersion: 0,
    swarmVersions: {},
    swarmKindVersions: {},
    jobs: {},
    lastChange: null,
    watching: false,
  });

  useEffect(() => {
    let source: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      if (closed) return;
      source = new EventSource("/api/events");
      source.addEventListener("hello", (e) => {
        const data = JSON.parse((e as MessageEvent).data) as { watching: boolean };
        // A (re)connection may have missed anything: every page refetches once.
        setState((s) => ({ ...s, status: "live", watching: data.watching, globalVersion: s.globalVersion + 1, registryVersion: s.registryVersion + 1 }));
      });
      source.addEventListener("change", (e) => {
        const change = JSON.parse((e as MessageEvent).data) as ChangeEvent;
        setState((s) => {
          const swarmVersions = { ...s.swarmVersions };
          const swarmKindVersions = { ...s.swarmKindVersions };
          // A server without `by_swarm` says only which swarms and which kinds:
          // then every swarm named gets every kind, which is what it did before.
          const bySwarm = change.by_swarm ?? Object.fromEntries(change.swarm_ids.map((id) => [id, change.kinds]));
          for (const id of change.swarm_ids) swarmVersions[id] = (swarmVersions[id] ?? 0) + 1;
          for (const [id, kinds] of Object.entries(bySwarm)) {
            const slot = { ...(swarmKindVersions[id] ?? {}) };
            for (const kind of kinds) slot[kind] = (slot[kind] ?? 0) + 1;
            swarmKindVersions[id] = slot;
          }
          const registry = change.swarm_ids.length === 0 || change.kinds.includes("registry");
          return {
            ...s,
            lastChange: change,
            globalVersion: s.globalVersion + 1,
            registryVersion: registry ? s.registryVersion + 1 : s.registryVersion,
            swarmVersions,
            swarmKindVersions,
            watching: change.watching ?? s.watching,
          };
        });
      });
      source.addEventListener("job", (e) => {
        const job = JSON.parse((e as MessageEvent).data) as Job;
        setState((s) => ({ ...s, jobs: { ...s.jobs, [job.id]: job } }));
      });
      source.onerror = () => {
        source?.close();
        source = null;
        setState((s) => ({ ...s, status: "offline" }));
        retry = setTimeout(connect, 3000);
      };
    };
    connect();
    return () => {
      closed = true;
      source?.close();
      if (retry) clearTimeout(retry);
    };
  }, []);

  const mergeJobs = useCallback((jobs: Job[]) => {
    setState((s) => {
      const merged = { ...s.jobs };
      for (const job of jobs) if (!merged[job.id] || merged[job.id].status === "running") merged[job.id] = job;
      return { ...s, jobs: merged };
    });
  }, []);

  const value = useMemo(() => ({ ...state, mergeJobs }), [state, mergeJobs]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive(): LiveValue {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive outside LiveProvider");
  return ctx;
}

/**
 * The key a swarm's resources refetch on: that swarm's own changes, and the
 * registry's. With `kinds`, only changes of those kinds count — the trace
 * page keys on `events`, the board on `threads` — so a lease or a budget
 * fold does not refetch a panel that does not show them.
 */
export function useSwarmVersion(id: string | undefined, kinds?: readonly ChangeKind[]): number {
  const live = useLive();
  if (!id) return live.registryVersion;
  if (!kinds) return (live.swarmVersions[id] ?? 0) + live.registryVersion;
  const slot = live.swarmKindVersions[id];
  let sum = live.registryVersion;
  if (slot) for (const kind of kinds) sum += slot[kind] ?? 0;
  return sum;
}

export type Resource<T> = {
  data: T | null;
  error: Error | null;
  loading: boolean;
  refreshing: boolean;
  reload: () => void;
  updatedAt: number | null;
};

/**
 * Stale-while-revalidate: the old data stays on screen while the loader runs
 * again. One request is in flight at a time; versions that move meanwhile are
 * folded into one more request after it lands, not one request per move, so
 * a burst of changes on disk is one refetch, not ten.
 */
export function useResource<T>(loader: (() => Promise<T>) | null, version: number, deps: unknown[] = []): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState<boolean>(Boolean(loader));
  const [refreshing, setRefreshing] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [nonce, setNonce] = useState(0);
  const seq = useRef(0);
  const inFlight = useRef(false);
  const pending = useRef(false);
  const hasData = useRef(false);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const depsKey = JSON.stringify(deps);

  // Reset when the identity of what we load changes (e.g. another swarm id).
  useEffect(() => {
    setData(null);
    hasData.current = false;
    setError(null);
    setLoading(Boolean(loader));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [depsKey]);

  const execute = useCallback(() => {
    const load = loaderRef.current;
    if (!load) return;
    inFlight.current = true;
    const mine = ++seq.current;
    if (hasData.current) setRefreshing(true);
    else setLoading(true);
    load()
      .then((value) => {
        if (mine !== seq.current) return;
        hasData.current = true;
        setData(value);
        setError(null);
        setUpdatedAt(Date.now());
      })
      .catch((err: unknown) => {
        if (mine !== seq.current) return;
        setError(err instanceof Error ? err : new Error(String(err)));
      })
      .finally(() => {
        if (mine === seq.current) {
          setLoading(false);
          setRefreshing(false);
        }
        inFlight.current = false;
        if (pending.current) {
          pending.current = false;
          execute();
        }
      });
  }, []);

  useEffect(() => {
    if (!loader) {
      setData(null);
      hasData.current = false;
      setLoading(false);
      setError(null);
      return;
    }
    if (inFlight.current) {
      pending.current = true;
      return;
    }
    execute();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version, nonce, depsKey, loader === null, execute]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return useMemo(() => ({ data, error, loading, refreshing, reload, updatedAt }), [data, error, loading, refreshing, reload, updatedAt]);
}
