import { sessionSchema, type Api, type AuthSession } from './contracts';
import { query } from './query';
type Cell<T> = { current: T };
export type SessionLoadState = {
  generation: Cell<number>;
  request: Cell<Promise<AuthSession | null> | null>;
  accept: (session: AuthSession) => void;
};
/** A request can only publish into the generation and request slot that created it. */
export function loadSession(
  api: Api,
  state: SessionLoadState,
  force = false,
): Promise<AuthSession | null> {
  if (state.request.current && !force) return state.request.current;
  const epoch = state.generation.current;
  const work = query(api, 'session', sessionSchema)
    .then((value) => {
      if (epoch !== state.generation.current || state.request.current !== work) return null;
      state.accept(value);
      return value;
    })
    .finally(() => {
      if (state.request.current === work) state.request.current = null;
    });
  state.request.current = work;
  return work;
}
