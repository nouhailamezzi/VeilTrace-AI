import {
  createThreatIntelligenceService,
  lookupCve,
  NVD_CVE_ENDPOINT,
  ThreatIntelligenceError,
} from './threatIntelligence';

const TEST_NOW = Date.parse('2026-11-27T00:00:00.000Z');
const LIVE_TEST_CVE_ID = 'CVE-2021-44228';

function getNowMs() {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function assertTest(condition, name) {
  if (!condition) {
    throw new Error(`Threat intelligence test failed: ${name}`);
  }
  return { name, passed: true };
}

function nvdResponse(cve, status = 200, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        return headers[name] ?? null;
      },
    },
    async json() {
      return { vulnerabilities: [{ cve }] };
    },
  };
}

function syntheticCve(id = 'CVE-2025-1234') {
  return {
    id,
    descriptions: [
      {
        lang: 'en',
        value: 'A mock vulnerability description; treat as untrusted text.',
      },
    ],
    metrics: {
      cvssMetricV31: [
        {
          type: 'Primary',
          cvssData: {
            baseScore: 8.1,
            baseSeverity: 'HIGH',
          },
        },
      ],
    },
    published: '2025-01-02T03:04:05.000',
    lastModified: '2025-02-03T04:05:06.000',
    references: [
      {
        url: 'https://vendor.example/advisory',
        source: 'vendor.example',
        tags: ['Vendor Advisory'],
      },
      { url: 'javascript:alert(1)' },
    ],
  };
}

function createService(fetchImpl, overrides = {}) {
  return createThreatIntelligenceService({
    fetchImpl,
    now: () => TEST_NOW,
    isOnline: () => true,
    ...overrides,
  });
}

async function expectError(promise, expectedCode) {
  try {
    await promise;
  } catch (error) {
    return error instanceof ThreatIntelligenceError && error.code === expectedCode;
  }
  return false;
}

/**
 * Runs deterministic NVD client tests. All fetch calls are mocked.
 */
export async function runThreatIntelligenceDevTest() {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      ok: false,
      status: 'disabled',
      code: 'threatIntel/dev-test-disabled-in-production',
    };
  }

  const checks = [];
  let fetchCount = 0;
  let approvedQuery = null;
  let sentUrl = null;
  let sentOptions = null;
  const approval = async (query) => {
    approvedQuery = query;
    return true;
  };

  const service = createService(async (url, options) => {
    fetchCount += 1;
    sentUrl = url;
    sentOptions = options;
    return nvdResponse(syntheticCve());
  });

  const liveResult = await service.lookupCve('cve-2025-1234', {
    approveQuery: approval,
    incidentData: {
      rawLogs: 'SYNTHETIC_LOCAL_ONLY',
      ipAddress: '192.0.2.1',
      username: 'synthetic-user',
      credentials: 'SYNTHETIC_LOCAL_ONLY',
    },
  });
  checks.push(
    assertTest(
      liveResult.source === 'live' && liveResult.cached === false,
      'live response is distinguished from cache'
    ),
    assertTest(
      approvedQuery?.url ===
        `${NVD_CVE_ENDPOINT}?cveId=CVE-2025-1234` &&
        approvedQuery.method === 'GET' &&
        Object.keys(approvedQuery).sort().join(',') === 'cveId,method,url' &&
        Object.isFrozen(approvedQuery),
      'approval receives the exact immutable outbound query'
    ),
    assertTest(
      sentUrl === `${NVD_CVE_ENDPOINT}?cveId=CVE-2025-1234` &&
        sentOptions.method === 'GET' &&
        sentOptions.body === undefined,
      'only the validated CVE identifier is sent'
    ),
    assertTest(
      liveResult.cveId === 'CVE-2025-1234' &&
        liveResult.descriptionTrust === 'untrusted_external' &&
        liveResult.cvssVersion === '3.1' &&
        liveResult.cvssScore === 8.1 &&
        liveResult.severity === 'HIGH' &&
        liveResult.published === '2025-01-02T03:04:05.000' &&
        liveResult.lastModified === '2025-02-03T04:05:06.000' &&
        liveResult.references.length === 1 &&
        liveResult.referencesTrust === 'untrusted_external',
      'NVD fields are extracted and external text is marked untrusted'
    ),
    assertTest(
      !Object.prototype.hasOwnProperty.call(liveResult, 'exploitationStatus'),
      'lookup does not make unsupported exploitation claims'
    )
  );

  const cachedResult = await service.lookupCve('CVE-2025-1234');
  checks.push(
    assertTest(
      cachedResult.source === 'cache' &&
        cachedResult.cached === true &&
        fetchCount === 1,
      'cache hits are identified and do not send another request'
    )
  );

  let onlineForCache = true;
  let offlineCacheFetchCount = 0;
  const offlineCacheService = createService(
    async () => {
      offlineCacheFetchCount += 1;
      return nvdResponse(syntheticCve('CVE-2025-2468'));
    },
    { isOnline: () => onlineForCache }
  );
  await offlineCacheService.lookupCve('CVE-2025-2468', {
    approveQuery: approval,
  });
  onlineForCache = false;
  const offlineCachedResult =
    await offlineCacheService.lookupCve('CVE-2025-2468');
  checks.push(
    assertTest(
      offlineCachedResult.source === 'cache' &&
        offlineCacheFetchCount === 1,
      'fresh cached data remains available offline'
    )
  );

  const missingCvssService = createService(async () =>
    nvdResponse({
      id: 'CVE-2025-5678',
      descriptions: [],
    })
  );
  const missingCvssResult = await missingCvssService.lookupCve(
    'CVE-2025-5678',
    { approveQuery: approval }
  );
  checks.push(
    assertTest(
      missingCvssResult.cvssVersion === null &&
        missingCvssResult.cvssScore === null &&
        missingCvssResult.severity === null &&
        missingCvssResult.description === null,
      'missing CVSS and description values remain null'
    )
  );

  let invalidIdFetchCount = 0;
  const invalidIdService = createService(async () => {
    invalidIdFetchCount += 1;
    return nvdResponse(syntheticCve());
  });
  checks.push(
    assertTest(
      await expectError(
        invalidIdService.lookupCve('CVE-1998-1234', { approveQuery: approval }),
        'threatIntel/invalid-cve-id'
      ) && invalidIdFetchCount === 0,
      'invalid CVE identifiers are rejected before network access'
    ),
    assertTest(
      await expectError(
        invalidIdService.lookupCve('CVE-2025-1234'),
        'threatIntel/approval-required'
      ) && invalidIdFetchCount === 0,
      'unapproved queries are never sent'
    ),
    assertTest(
      await expectError(
        invalidIdService.lookupCve('CVE-2025-1234', {
          approveQuery: async () => false,
        }),
        'threatIntel/approval-denied'
      ) && invalidIdFetchCount === 0,
      'denied query approval prevents network access'
    )
  );

  const jsonTimeoutService = createService(async () => ({
    ok: true,
    status: 200,
    json: () => new Promise(() => {}),
  }));
  checks.push(
    assertTest(
      await expectError(
        jsonTimeoutService.lookupCve('CVE-2025-1234', {
          approveQuery: approval,
          timeoutMs: 1,
        }),
        'threatIntel/timeout'
      ),
      'timeout also covers a stalled response body'
    )
  );

  const offlineService = createService(
    async () => {
      throw new Error('Offline test must not call fetch.');
    },
    { isOnline: () => false }
  );
  checks.push(
    assertTest(
      await expectError(
        offlineService.lookupCve('CVE-2025-1234', { approveQuery: approval }),
        'threatIntel/offline'
      ),
      'offline lookups fail explicitly'
    )
  );

  const rateLimitedService = createService(
    async () => nvdResponse({}, 429, { 'Retry-After': '30' })
  );
  let http429Error;
  try {
    await rateLimitedService.lookupCve('CVE-2025-1234', {
      approveQuery: approval,
    });
  } catch (error) {
    http429Error = error;
  }
  checks.push(
    assertTest(
      http429Error?.code === 'threatIntel/http-429' &&
        http429Error.status === 429 &&
        http429Error.retryAfterSeconds === 30,
      'HTTP 429 and Retry-After are surfaced'
    )
  );

  const timeoutService = createService(
    () => new Promise(() => {})
  );
  checks.push(
    assertTest(
      await expectError(
        timeoutService.lookupCve('CVE-2025-1234', {
          approveQuery: approval,
          timeoutMs: 1,
        }),
        'threatIntel/timeout'
      ),
      'request timeouts are surfaced'
    )
  );

  const corsService = createService(async () => {
    throw new TypeError('Network request failed');
  });
  checks.push(
    assertTest(
      await expectError(
        corsService.lookupCve('CVE-2025-1234', { approveQuery: approval }),
        'threatIntel/network-or-cors-error'
      ),
      'network and browser CORS failures are surfaced'
    )
  );

  const unavailableService = createService(async () =>
    nvdResponse({}, 503)
  );
  checks.push(
    assertTest(
      await expectError(
        unavailableService.lookupCve('CVE-2025-1234', {
          approveQuery: approval,
        }),
        'threatIntel/service-unavailable'
      ),
      'unavailable NVD service responses are surfaced'
    )
  );

  const rateGuardService = createService(
    async () => nvdResponse(syntheticCve()),
    {
      maxRequestsPerWindow: 1,
      rateWindowMs: 30_000,
    }
  );
  await rateGuardService.lookupCve('CVE-2025-1234', {
    approveQuery: approval,
  });
  checks.push(
    assertTest(
      await expectError(
        rateGuardService.lookupCve('CVE-2025-9876', {
          approveQuery: approval,
        }),
        'threatIntel/client-rate-limited'
      ),
      'local NVD rate guard prevents excess requests'
    )
  );

  const summary = {
    ok: checks.every((check) => check.passed),
    total: checks.length,
    passed: checks.filter((check) => check.passed).length,
    failed: checks.filter((check) => !check.passed).length,
    checks,
    liveApiRequests: 0,
  };
  console.info('[Threat Intelligence DevTest]', {
    ok: summary.ok,
    passed: summary.passed,
    total: summary.total,
    liveApiRequests: summary.liveApiRequests,
  });
  return summary;
}

/**
 * Performs one manually confirmed live lookup for the fixed public CVE.
 */
export async function runThreatIntelligenceLiveTest() {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      ok: false,
      status: 'disabled',
      code: 'threatIntel/live-test-disabled-in-production',
    };
  }

  const requestUrl = `${NVD_CVE_ENDPOINT}?cveId=${encodeURIComponent(
    LIVE_TEST_CVE_ID
  )}`;
  if (typeof window === 'undefined' || typeof window.confirm !== 'function') {
    return {
      ok: false,
      status: 'blocked',
      code: 'threatIntel/confirmation-unavailable',
      requestUrl,
    };
  }

  const confirmed = window.confirm(
    `Send one live NVD request for ${LIVE_TEST_CVE_ID}?\n\n${requestUrl}\n\nOnly this public CVE identifier will be sent.`
  );
  if (!confirmed) {
    return {
      ok: false,
      status: 'cancelled',
      code: 'threatIntel/live-test-cancelled',
      requestUrl,
    };
  }

  const startedAt = getNowMs();
  try {
    const result = await lookupCve(LIVE_TEST_CVE_ID, {
      forceRefresh: true,
      approveQuery: (query) =>
        query.method === 'GET' &&
        query.cveId === LIVE_TEST_CVE_ID &&
        query.url === requestUrl,
    });

    return {
      ok: true,
      cveId: result.cveId,
      cvssScore: result.cvssScore,
      severity: result.severity,
      description: result.description,
      descriptionTrust: result.descriptionTrust,
      published: result.published,
      lastModified: result.lastModified,
      source: result.source,
      retrievedAt: result.retrievedAt,
      requestDurationMs: Math.round(getNowMs() - startedAt),
    };
  } catch (error) {
    return {
      ok: false,
      status: 'error',
      code:
        typeof error?.code === 'string'
          ? error.code
          : 'threatIntel/live-test-failed',
      requestUrl,
      requestDurationMs: Math.round(getNowMs() - startedAt),
    };
  }
}

if (
  import.meta.env.DEV &&
  !import.meta.env.PROD &&
  typeof window !== 'undefined'
) {
  window.__veiltraceThreatIntelligenceTest = runThreatIntelligenceDevTest;
  window.__veiltraceThreatIntelligenceLiveTest =
    runThreatIntelligenceLiveTest;
}
