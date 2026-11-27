const NVD_CVE_ENDPOINT =
  'https://services.nvd.nist.gov/rest/json/cves/2.0';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CACHE_TTL_MS = 10 * 60 * 1000;
const NVD_UNAUTHENTICATED_REQUEST_LIMIT = 5;
const NVD_RATE_WINDOW_MS = 30_000;
const MAX_CACHE_ENTRIES = 100;

const CVE_ID_PATTERN = /^CVE-(\d{4})-(\d{4,})$/i;

export class ThreatIntelligenceError extends Error {
  constructor(code, message, metadata = {}) {
    super(message);
    this.name = 'ThreatIntelligenceError';
    this.code = code;
    this.status = metadata.status;
    this.retryAfterSeconds = metadata.retryAfterSeconds;
  }
}

function isBrowserOnline() {
  return typeof navigator === 'undefined' || navigator.onLine !== false;
}

function normalizeCveId(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const cveId = value.trim().toUpperCase();
  const match = CVE_ID_PATTERN.exec(cveId);
  return match && Number(match[1]) >= 1999 ? cveId : null;
}

function readRetryAfter(response, now) {
  const header = response.headers?.get?.('Retry-After');
  if (!header) {
    return undefined;
  }

  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.ceil(seconds);
  }

  const retryAt = Date.parse(header);
  return Number.isFinite(retryAt)
    ? Math.max(0, Math.ceil((retryAt - now) / 1000))
    : undefined;
}

function getCvss(cve) {
  const metricVersions = [
    ['cvssMetricV40', '4.0'],
    ['cvssMetricV31', '3.1'],
    ['cvssMetricV30', '3.0'],
    ['cvssMetricV2', '2.0'],
  ];

  for (const [field, version] of metricVersions) {
    const metrics = cve.metrics?.[field];
    if (!Array.isArray(metrics) || metrics.length === 0) {
      continue;
    }

    const metric =
      metrics.find((candidate) => candidate?.type === 'Primary') ?? metrics[0];
    const cvssData = metric?.cvssData;
    const score =
      typeof cvssData?.baseScore === 'number' &&
      Number.isFinite(cvssData.baseScore)
        ? cvssData.baseScore
        : null;
    const severity =
      typeof cvssData?.baseSeverity === 'string'
        ? cvssData.baseSeverity
        : typeof metric?.baseSeverity === 'string'
          ? metric.baseSeverity
          : typeof cvssData?.severity === 'string'
            ? cvssData.severity
            : null;

    return { version, score, severity };
  }

  return { version: null, score: null, severity: null };
}

function getDescription(cve) {
  if (!Array.isArray(cve.descriptions)) {
    return null;
  }

  const description =
    cve.descriptions.find((entry) => entry?.lang === 'en') ??
    cve.descriptions.find((entry) => typeof entry?.value === 'string');

  return typeof description?.value === 'string' ? description.value : null;
}

function getReferences(cve) {
  if (!Array.isArray(cve.references)) {
    return [];
  }

  return cve.references.flatMap((reference) => {
    if (typeof reference?.url !== 'string') {
      return [];
    }

    try {
      const url = new URL(reference.url);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        return [];
      }

      return [
        {
          url: url.href,
          source:
            typeof reference.source === 'string' ? reference.source : null,
          tags: Array.isArray(reference.tags)
            ? reference.tags.filter((tag) => typeof tag === 'string')
            : [],
        },
      ];
    } catch {
      return [];
    }
  });
}

function normalizeCveRecord(cve, sourceUrl, retrievedAt) {
  if (!cve || typeof cve.id !== 'string') {
    throw new ThreatIntelligenceError(
      'threatIntel/invalid-response',
      'NVD returned a malformed vulnerability record.'
    );
  }

  const cvss = getCvss(cve);
  return {
    cveId: cve.id,
    description: getDescription(cve),
    descriptionTrust: 'untrusted_external',
    cvssVersion: cvss.version,
    cvssScore: cvss.score,
    severity: cvss.severity,
    published: typeof cve.published === 'string' ? cve.published : null,
    lastModified:
      typeof cve.lastModified === 'string' ? cve.lastModified : null,
    references: getReferences(cve),
    referencesTrust: 'untrusted_external',
    source: 'live',
    cached: false,
    sourceUrl,
    retrievedAt,
  };
}

function cloneResult(result, source) {
  return {
    ...result,
    references: result.references.map((reference) => ({
      ...reference,
      tags: [...reference.tags],
    })),
    source,
    cached: source === 'cache',
  };
}

/**
 * Creates a NVD CVE lookup service. Dependencies are injectable so tests can
 * use mocked responses without contacting NVD.
 *
 * @param {{
 *   fetchImpl?: typeof fetch,
 *   now?: () => number,
 *   isOnline?: () => boolean,
 *   cacheTtlMs?: number,
 *   maxRequestsPerWindow?: number,
 *   rateWindowMs?: number,
 * }} [dependencies]
 */
export function createThreatIntelligenceService(dependencies = {}) {
  const fetchImpl =
    dependencies.fetchImpl ??
    (typeof globalThis.fetch === 'function'
      ? globalThis.fetch.bind(globalThis)
      : null);
  const now = dependencies.now ?? Date.now;
  const isOnline = dependencies.isOnline ?? isBrowserOnline;
  const cacheTtlMs = dependencies.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  const maxRequestsPerWindow =
    dependencies.maxRequestsPerWindow ?? NVD_UNAUTHENTICATED_REQUEST_LIMIT;
  const rateWindowMs = dependencies.rateWindowMs ?? NVD_RATE_WINDOW_MS;
  const cache = new Map();
  const requestTimes = [];

  function enforceRateLimit(requestedAt) {
    while (
      requestTimes.length > 0 &&
      requestedAt - requestTimes[0] >= rateWindowMs
    ) {
      requestTimes.shift();
    }

    if (requestTimes.length >= maxRequestsPerWindow) {
      const retryAfterSeconds = Math.ceil(
        (requestTimes[0] + rateWindowMs - requestedAt) / 1000
      );
      throw new ThreatIntelligenceError(
        'threatIntel/client-rate-limited',
        'The local NVD request limit has been reached.',
        { retryAfterSeconds }
      );
    }

    requestTimes.push(requestedAt);
  }

  async function lookupCve(
    input,
    {
      approveQuery,
      signal,
      timeoutMs = DEFAULT_TIMEOUT_MS,
      forceRefresh = false,
    } = {}
  ) {
    const cveId = normalizeCveId(input);
    if (!cveId) {
      throw new ThreatIntelligenceError(
        'threatIntel/invalid-cve-id',
        'Provide a valid public CVE identifier (for example, CVE-2024-1234).'
      );
    }

    const cachedEntry = cache.get(cveId);
    const lookupStartedAt = now();
    if (
      !forceRefresh &&
      cachedEntry &&
      cachedEntry.expiresAt > lookupStartedAt
    ) {
      return cloneResult(cachedEntry.result, 'cache');
    }
    if (cachedEntry) {
      cache.delete(cveId);
    }

    if (!isOnline()) {
      throw new ThreatIntelligenceError(
        'threatIntel/offline',
        'NVD lookup requires an internet connection and no fresh cached result is available.'
      );
    }

    const requestUrl = `${NVD_CVE_ENDPOINT}?cveId=${encodeURIComponent(cveId)}`;
    if (typeof approveQuery !== 'function') {
      throw new ThreatIntelligenceError(
        'threatIntel/approval-required',
        'Explicit approval is required for this exact outbound NVD query.'
      );
    }

    let approved;
    try {
      approved = await approveQuery(
        Object.freeze({
          method: 'GET',
          url: requestUrl,
          cveId,
        })
      );
    } catch {
      throw new ThreatIntelligenceError(
        'threatIntel/approval-failed',
        'The NVD query approval handler failed.'
      );
    }
    if (approved !== true) {
      throw new ThreatIntelligenceError(
        'threatIntel/approval-denied',
        'The exact NVD query was not approved.'
      );
    }

    if (!fetchImpl) {
      throw new ThreatIntelligenceError(
        'threatIntel/service-unavailable',
        'Fetch is unavailable in this environment.'
      );
    }
    if (signal?.aborted) {
      throw new ThreatIntelligenceError(
        'threatIntel/aborted',
        'The NVD request was aborted before it started.'
      );
    }
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new ThreatIntelligenceError(
        'threatIntel/invalid-timeout',
        'Timeout must be a positive finite number of milliseconds.'
      );
    }

    enforceRateLimit(now());

    const controller = new AbortController();
    let timeoutId;
    let timeoutExpired = false;
    let externalAbortHandler;
    let rejectTimeout;
    let rejectExternalAbort;
    const timeoutError = new ThreatIntelligenceError(
      'threatIntel/timeout',
      'The NVD request timed out.'
    );
    const externalAbortError = new ThreatIntelligenceError(
      'threatIntel/aborted',
      'The NVD request was aborted.'
    );
    const timeoutPromise = new Promise((resolve, reject) => {
      rejectTimeout = reject;
    });
    const externalAbortPromise = signal
      ? new Promise((resolve, reject) => {
          rejectExternalAbort = reject;
        })
      : new Promise(() => {});

    timeoutId = setTimeout(() => {
      timeoutExpired = true;
      controller.abort();
      rejectTimeout(timeoutError);
    }, timeoutMs);

    if (signal) {
      externalAbortHandler = () => {
        controller.abort();
        rejectExternalAbort(externalAbortError);
      };
      signal.addEventListener('abort', externalAbortHandler, { once: true });
    }

    try {
      const response = await Promise.race([
        Promise.resolve().then(() =>
          fetchImpl(requestUrl, {
            method: 'GET',
            mode: 'cors',
            headers: { Accept: 'application/json' },
            signal: controller.signal,
          })
        ),
        timeoutPromise,
        externalAbortPromise,
      ]);

      if (response.status === 429) {
        throw new ThreatIntelligenceError(
          'threatIntel/http-429',
          'NVD rate limit reached; retry after the indicated delay.',
          {
            status: 429,
            retryAfterSeconds: readRetryAfter(response, now()),
          }
        );
      }
      if (response.status >= 500) {
        throw new ThreatIntelligenceError(
          'threatIntel/service-unavailable',
          'The NVD service is currently unavailable.',
          { status: response.status }
        );
      }
      if (!response.ok) {
        throw new ThreatIntelligenceError(
          response.status === 404
            ? 'threatIntel/not-found'
            : 'threatIntel/http-error',
          'NVD rejected the vulnerability lookup.',
          { status: response.status }
        );
      }

      let payload;
      try {
        payload = await Promise.race([
          Promise.resolve().then(() => response.json()),
          timeoutPromise,
          externalAbortPromise,
        ]);
      } catch (error) {
        if (error instanceof ThreatIntelligenceError) {
          throw error;
        }
        throw new ThreatIntelligenceError(
          'threatIntel/invalid-response',
          'NVD returned invalid JSON.'
        );
      }

      if (!Array.isArray(payload?.vulnerabilities)) {
        throw new ThreatIntelligenceError(
          'threatIntel/invalid-response',
          'NVD returned an unexpected response shape.'
        );
      }

      const matchingRecord = payload.vulnerabilities.find(
        (entry) =>
          typeof entry?.cve?.id === 'string' &&
          entry.cve.id.toUpperCase() === cveId
      );
      if (!matchingRecord) {
        throw new ThreatIntelligenceError(
          'threatIntel/not-found',
          'NVD returned no matching vulnerability for this CVE identifier.'
        );
      }

      const result = normalizeCveRecord(
        matchingRecord.cve,
        requestUrl,
        new Date(now()).toISOString()
      );
      cache.set(cveId, {
        result,
        expiresAt: now() + cacheTtlMs,
      });
      while (cache.size > MAX_CACHE_ENTRIES) {
        cache.delete(cache.keys().next().value);
      }
      return cloneResult(result, 'live');
    } catch (error) {
      if (error instanceof ThreatIntelligenceError) {
        throw error;
      }
      if (timeoutExpired) {
        throw timeoutError;
      }
      if (signal?.aborted) {
        throw externalAbortError;
      }
      if (error instanceof TypeError) {
        throw new ThreatIntelligenceError(
          'threatIntel/network-or-cors-error',
          'NVD could not be reached. This may be a network or browser CORS failure.'
        );
      }
      throw new ThreatIntelligenceError(
        'threatIntel/request-failed',
        'The NVD request failed unexpectedly.'
      );
    } finally {
      clearTimeout(timeoutId);
      if (signal && externalAbortHandler) {
        signal.removeEventListener('abort', externalAbortHandler);
      }
    }
  }

  return { lookupCve };
}

const defaultService = createThreatIntelligenceService();

export const lookupCve = (...args) => defaultService.lookupCve(...args);
export { NVD_CVE_ENDPOINT };
