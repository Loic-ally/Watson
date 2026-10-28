// Thin fetch helpers against the Rust backend. Cookies carry the session.

export const api = (path: string, opts?: RequestInit) =>
  fetch(path, { credentials: "same-origin", ...opts });

export const postJson = (path: string, body: unknown) =>
  api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

export async function checkAuth(): Promise<boolean> {
  try {
    return (await api("/api/status")).ok;
  } catch {
    return false;
  }
}
