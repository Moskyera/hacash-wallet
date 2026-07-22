export const OFFICIAL_NODE_URL = "http://nodeapi.hacash.org";

const OFFICIAL_NODE_HOSTS = new Set(["nodeapi.hacash.org", "nodeapi.org"]);

export function isOfficialNodeUrl(value: string): boolean {
  const raw = value.trim();
  if (!raw) return false;

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  if (!hasScheme && raw.startsWith("/")) return false;
  const candidate = hasScheme ? raw : `http://${raw}`;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return false;
  }

  return (
    (url.protocol === "http:" || url.protocol === "https:") &&
    OFFICIAL_NODE_HOSTS.has(url.hostname.toLowerCase()) &&
    url.username === "" &&
    url.password === "" &&
    url.port === "" &&
    url.pathname === "/" &&
    url.search === "" &&
    url.hash === ""
  );
}
