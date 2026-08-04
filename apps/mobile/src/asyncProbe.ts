export type AsyncProbe<T> =
  | { status: "loading"; value: T }
  | { status: "ready"; value: T }
  | { status: "failed"; value: T; message: string };

export function loadingProbe<T>(value: T): AsyncProbe<T> {
  return { status: "loading", value };
}

export function readyProbe<T>(value: T): AsyncProbe<T> {
  return { status: "ready", value };
}

export function failedProbe<T>(value: T, message: string): AsyncProbe<T> {
  return { status: "failed", value, message };
}

export type KeyedRequest<K> = {
  key: K;
  generation: number;
};

export function isCurrentKeyedRequest<K>(
  activeKey: K | null,
  currentGeneration: number,
  request: KeyedRequest<K>,
): boolean {
  return activeKey === request.key && currentGeneration === request.generation;
}
