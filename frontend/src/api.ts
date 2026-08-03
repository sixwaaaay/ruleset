import type { Rule, RulesetDetail, RulesetSummary } from './types';
import i18n from './i18n';

// Rule types supported by the backend (keep in sync with the server enum; send uppercase)
export const RULE_TYPES: string[] = [
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'DOMAIN-KEYWORD',
  'DOMAIN-WILDCARD',
  'DOMAIN-REGEX',
  'GEOSITE',
  'IP-CIDR',
  'IP-CIDR6',
  'IP-SUFFIX',
  'IP-ASN',
  'GEOIP',
  'SRC-GEOIP',
  'SRC-IP-ASN',
  'SRC-IP-CIDR',
  'SRC-IP-SUFFIX',
  'DST-PORT',
  'SRC-PORT',
  'IN-PORT',
  'IN-TYPE',
  'IN-USER',
  'IN-NAME',
  'PROCESS-PATH',
  'PROCESS-PATH-REGEX',
  'PROCESS-NAME',
  'PROCESS-NAME-REGEX',
  'UID',
  'NETWORK',
  'DSCP',
  'MATCH',
];

const TOKEN_KEY = 'ruleset_admin_token';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? '';
}

export function setToken(token: string): void {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

async function request<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const token = getToken();
  const res = await fetch(path, {
    method: init?.method ?? 'GET',
    headers: {
      ...(init?.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
  });

  if (res.status === 401) {
    setToken('');
    throw new ApiError(401, i18n.t('auth.expired'));
  }
  if (res.status === 204) {
    return undefined as T;
  }

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    const message =
      data && typeof data === 'object' && 'error' in data
        ? String((data as { error: unknown }).error)
        : i18n.t('auth.requestFailed', { status: res.status });
    throw new ApiError(res.status, message);
  }
  return data as T;
}

export const listRulesets = () => request<RulesetSummary[]>('/rulesets');
export const getRuleset = (slug: string) =>
  request<RulesetDetail>(`/rulesets/${encodeURIComponent(slug)}`);
export const createRuleset = (name: string, slug?: string) =>
  request<RulesetSummary>('/rulesets', { method: 'POST', body: { name, slug } });
export const updateRuleset = (slug: string, patch: { name?: string; require_key?: boolean }) =>
  request<RulesetDetail>(`/rulesets/${encodeURIComponent(slug)}`, { method: 'PATCH', body: patch });
export const deleteRuleset = (slug: string) =>
  request<void>(`/rulesets/${encodeURIComponent(slug)}`, { method: 'DELETE' });
export const addRule = (slug: string, rule: Rule) =>
  request<void>(`/rulesets/${encodeURIComponent(slug)}/rules`, { method: 'POST', body: rule });
export const deleteRule = (slug: string, rule: Rule) =>
  request<void>(`/rulesets/${encodeURIComponent(slug)}/rules`, {
    method: 'DELETE',
    body: rule,
  });

/** Build the full public URL used by the client (appends the read key when protected) */
export function fullPublicUrl(detail: RulesetDetail): string {
  const base = `${location.origin}${detail.url}`;
  return detail.protected && detail.read_key ? `${base}?k=${detail.read_key}` : base;
}