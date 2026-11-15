import { useEffect, useMemo, useState } from 'preact/hooks';
import { LookupClient, type ViewState } from './client';

/** One client per page, connected for the page's lifetime. */
export function useLookupClient(factory?: () => LookupClient): { client: LookupClient; state: ViewState } {
  const client = useMemo(() => (factory ? factory() : new LookupClient()), []);
  const [state, setState] = useState<ViewState>(client.state);
  useEffect(() => {
    const unsubscribe = client.subscribe(setState);
    if (!client.state.connected) client.connect();
    return () => {
      unsubscribe();
      client.close();
    };
  }, [client]);
  return { client, state };
}

/** Current time, refreshed every `ms` (for "≈45 s" and "3 h ago"). */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}
