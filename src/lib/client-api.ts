import { requestStepUp } from "./step-up-client";

export async function api<T>(path: string, init?: RequestInit, allowStepUp = true): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  });
  const data = (await response.json().catch(() => ({}))) as {
    error?: string;
    code?: string;
    twoFactor?: boolean;
  };
  if (!response.ok) {
    if (allowStepUp && response.status === 403 && data.code === "step_up_required") {
      await requestStepUp({ twoFactor: data.twoFactor === true });
      return api<T>(path, init, false);
    }
    throw new Error(data.error ?? "No se pudo completar");
  }
  return data as T;
}
