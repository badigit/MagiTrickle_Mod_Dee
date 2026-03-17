export function isValidWildcard(pattern: string): boolean {
  return /^(?!\.)(?!.*\.$)(?!.*\.\.)(?!.*\*\*)[a-zA-Z0-9\-.*?]+$/.test(pattern);
}

export function isValidDomain(pattern: string): boolean {
  return /^(?!\.)(?!.*\.$)(?!.*\.\.)[a-zA-Z0-9\-.]+$/.test(pattern);
}

export function isValidNamespace(pattern: string): boolean {
  return isValidDomain(pattern);
}

export function isValidSubnet(pattern: string): boolean {
  let matches = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(pattern);
  return !(
    !matches ||
    parseInt(matches[1]) > 255 ||
    parseInt(matches[2]) > 255 ||
    parseInt(matches[3]) > 255 ||
    parseInt(matches[4]) > 255 ||
    (matches[5] != "" && parseInt(matches[5]) > 32)
  );
}

function isValidIPv6(ip: string): boolean {
  return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(":");
}

export function isValidSubnet6(pattern: string): boolean {
  const parts = pattern.split("/");
  if (parts.length === 1) {
    return isValidIPv6(parts[0]);
  }

  if (parts.length !== 2) return false;

  const prefix = Number(parts[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
    return false;
  }

  return isValidIPv6(parts[0]);
}

export function isValidRegex(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch (e) {
    if (e instanceof SyntaxError) {
      return false;
    }
    return false;
  }
}

/**
 * Извлекает hostname из строки, если она похожа на URL (содержит :// или начинается с http/https).
 * Убирает протокол, путь, query, фрагмент, порт и www-префикс.
 */
export function extractDomainFromUrl(text: string): string {
  const trimmed = text.trim();
  if (!trimmed) return trimmed;
  try {
    // Пробуем парсить как URL только если есть признаки URL
    if (/^https?:\/\//i.test(trimmed) || /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
      const url = new URL(trimmed);
      return url.hostname.replace(/^www\./i, "");
    }
  } catch {
    // не URL — возвращаем как есть
  }
  return trimmed;
}

export const VALIDATOP_MAP: Record<string, (pattern: string) => boolean> = {
  regex: isValidRegex,
  wildcard: isValidWildcard,
  domain: isValidDomain,
  namespace: isValidNamespace,
  subnet: isValidSubnet,
  subnet6: isValidSubnet6,
};
