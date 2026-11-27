import {
  createThreatIntelligenceService,
  NVD_CVE_ENDPOINT,
} from './threatIntelligence.js';
import {
  createInvestigationService,
  INFERENCE_SOURCES,
  OPERATING_MODES,
} from './investigationService.js';

const TEST_CVE_ID = 'CVE-2025-1234';
const TEST_NOW = Date.parse('2026-11-27T00:00:00.000Z');
const TEST_EVIDENCE = [
  { id: 'E-1', content: 'Repeated failed sign-in events were recorded.' },
];

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function makeReport({ evidenceId = 'E-1', cveId = null } = {}) {
  return JSON.stringify({
    incidentSummary: 'Repeated failed sign-in events were observed.',
    riskAssessment: {
      level: 'medium',
      rationale: 'The supplied evidence shows repeated failures.',
      evidenceReferences: [evidenceId],
    },
    observedFacts: [
      {
        statement: 'Repeated failed sign-in events were recorded.',
        evidenceReferences: [evidenceId],
      },
    ],
    possibleExplanations: [
      {
        hypothesis: 'The activity may reflect automated probing.',
        evidenceReferences: [evidenceId],
      },
    ],
    evidenceReferences: [evidenceId],
    relevantVulnerabilities: cveId
      ? [
          {
            cveId,
            relevance: 'Review exposure if the affected software is present.',
            evidenceReferences: [evidenceId],
          },
        ]
      : [],
    recommendedDefensiveActions: [
      {
        action: 'Review authentication controls and relevant system logs.',
        evidenceReferences: [evidenceId],
      },
    ],
    limitationsAndUncertainty: [
      'The assessment is limited to the supplied evidence.',
    ],
  });
}

function routeSuccess(
  text,
  inferenceSource = INFERENCE_SOURCES.ON_DEVICE,
  model = 'gemini-nano'
) {
  return {
    ok: true,
    status: 'success',
    selectedMode: OPERATING_MODES.PRIVATE_AI,
    inferenceSource,
    model,
    durationMs: 42,
    fallbackReason: null,
    text,
  };
}

function createFirewall(sanitizedIncident, observed = {}) {
  return {
    async validateCloudPayload(payload) {
      observed.firewallCalls = (observed.firewallCalls ?? 0) + 1;
      observed.firewallInputs = observed.firewallInputs ?? [];
      observed.firewallInputs.push(payload);

      if (payload?.sanitized === false) {
        return {
          allowed: true,
          sanitizedPrompt: JSON.stringify(sanitizedIncident),
        };
      }
      return {
        allowed: true,
        sanitizedPrompt: payload.prompt,
      };
    },
  };
}

function createCloudRouter({ text, observed }) {
  return async (payload, options) => {
    observed.routeCalls = (observed.routeCalls ?? 0) + 1;
    observed.routePayload = payload;
    observed.routeOptions = options;

    const firewallResult =
      await options.privacyFirewall.validateCloudPayload(payload);
    if (firewallResult.allowed !== true) {
      return {
        ok: false,
        status: 'blocked',
        selectedMode: options.mode,
        inferenceSource: 'none',
        model: null,
        durationMs: 1,
        fallbackReason: firewallResult.code,
        code: firewallResult.code,
        message: firewallResult.reason,
      };
    }

    observed.executorPrompt = firewallResult.sanitizedPrompt;
    const consent = await options.consentHandler(
      Object.freeze({ ...payload }),
      {
        sanitizedPrompt: firewallResult.sanitizedPrompt,
        payloadFingerprint: 'mock-payload-fingerprint',
      }
    );
    if (consent !== true) {
      return {
        ok: false,
        status: 'blocked',
        selectedMode: options.mode,
        inferenceSource: 'none',
        model: null,
        durationMs: 2,
        fallbackReason: 'hybridRouter/consent-denied',
        code: 'hybridRouter/consent-denied',
        message: 'Explicit cloud consent was denied.',
      };
    }

    return {
      ok: true,
      status: 'success',
      selectedMode: options.mode,
      inferenceSource: INFERENCE_SOURCES.IN_CLOUD,
      model: 'mock-cloud-model',
      durationMs: 23,
      fallbackReason: null,
      text,
    };
  };
}

function createNvdService(observed = {}) {
  return createThreatIntelligenceService({
    now: () => TEST_NOW,
    isOnline: () => true,
    fetchImpl: async (url) => {
      observed.fetchCalls = (observed.fetchCalls ?? 0) + 1;
      observed.fetchUrl = String(url);
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        async json() {
          return {
            vulnerabilities: [
              {
                cve: {
                  id: TEST_CVE_ID,
                  descriptions: [
                    {
                      lang: 'en',
                      value: 'Mock NVD description; treat as untrusted text.',
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
                  ],
                },
              },
            ],
          };
        },
      };
    },
  });
}

async function runAsyncCase(name, callback) {
  try {
    await callback();
    return { name, passed: true };
  } catch (error) {
    return {
      name,
      passed: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Development-only orchestration tests. All NVD responses, router results,
 * firewall results, and consent decisions are mocked.
 */
export async function runInvestigationServiceDevTest() {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      ok: false,
      status: 'disabled',
      code: 'investigation/dev-test-disabled-in-production',
    };
  }

  const cases = [];

  cases.push(
    await runAsyncCase('successful private investigation', async () => {
      const observed = {};
      const service = createInvestigationService({
        routeInference: async (payload, options) => {
          observed.payload = payload;
          observed.options = options;
          return routeSuccess(makeReport());
        },
      });
      const result = await service.investigateIncident({
        mode: OPERATING_MODES.PRIVATE_AI,
        incident: {
          incidentSummary: 'Review this local incident.',
          evidence: TEST_EVIDENCE,
        },
      });
      assert(result.ok && result.status === 'success', 'Private investigation did not succeed.');
      assert(
        result.inferenceSource === INFERENCE_SOURCES.ON_DEVICE,
        'Private source was not preserved.'
      );
      assert(result.model === 'gemini-nano' && result.durationMs === 42, 'Inference metadata changed.');
      assert(result.report?.observedFacts[0].evidenceReferences[0] === 'E-1', 'Report did not validate.');
      assert(observed.options.mode === OPERATING_MODES.PRIVATE_AI, 'Private mode was not routed.');
    })
  );

  cases.push(
    await runAsyncCase('approved sanitized cloud investigation', async () => {
      const observed = {};
      const nvd = createNvdService(observed);
      const firewall = createFirewall(
        {
          incidentSummary: 'Sanitized sign-in anomaly.',
          evidence: [
            { id: 'E-1', content: 'Repeated failed sign-in events.' },
          ],
        },
        observed
      );
      const service = createInvestigationService({
        lookupCve: nvd.lookupCve,
        routeInference: createCloudRouter({
          text: makeReport({ cveId: TEST_CVE_ID }),
          observed,
        }),
      });
      let nvdApprovalCalls = 0;
      let consentCalls = 0;
      const result = await service.investigateIncident(
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          incident: {
            incidentSummary: 'Raw incident summary.',
            evidence: TEST_EVIDENCE,
          },
          vulnerabilityIds: [TEST_CVE_ID],
        },
        {
          privacyFirewall: firewall,
          consentHandler: (_payload, context) => {
            consentCalls += 1;
            return context.sanitizedPrompt === observed.executorPrompt;
          },
          approveNvdQuery: (query) => {
            nvdApprovalCalls += 1;
            return (
              query.method === 'GET' &&
              query.cveId === TEST_CVE_ID &&
              query.url === `${NVD_CVE_ENDPOINT}?cveId=${TEST_CVE_ID}`
            );
          },
        }
      );
      assert(result.ok && result.status === 'success', 'Approved cloud investigation failed.');
      assert(
        result.inferenceSource === INFERENCE_SOURCES.IN_CLOUD,
        'Cloud source was not preserved.'
      );
      assert(observed.fetchCalls === 1 && nvdApprovalCalls === 1, 'NVD approval/query count was incorrect.');
      assert(consentCalls === 1, 'Cloud consent was not required exactly once.');
      assert(result.vulnerabilityIntelligence[0].source === 'live', 'NVD provenance was lost.');
      assert(
        result.report.relevantVulnerabilities[0].cvssScore === 8.1 &&
          result.report.relevantVulnerabilities[0].retrievedAt ===
            new Date(TEST_NOW).toISOString(),
        'NVD values or retrieval provenance were not preserved.'
      );
    })
  );

  cases.push(
    await runAsyncCase('plain firewall output preserves only included evidence IDs', async () => {
      const observed = {};
      const service = createInvestigationService({
        routeInference: createCloudRouter({
          text: makeReport(),
          observed,
        }),
      });
      const result = await service.investigateIncident(
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          incident: {
            incidentSummary: 'Original incident summary.',
            evidence: TEST_EVIDENCE,
          },
        },
        {
          privacyFirewall: {
            async validateCloudPayload(payload) {
              return {
                allowed: true,
                sanitizedPrompt:
                  payload.sanitized === false
                    ? 'Sanitized incident narrative for E-1.'
                    : payload.prompt,
              };
            },
          },
          consentHandler: (_payload, context) =>
            context.sanitizedPrompt === observed.executorPrompt,
        }
      );
      assert(result.ok, 'Plain sanitized firewall output was rejected.');
      assert(
        result.report.evidenceReferences.length === 1 &&
          result.report.evidenceReferences[0] === 'E-1',
        'Evidence context did not match IDs retained by the firewall output.'
      );
    })
  );

  cases.push(
    await runAsyncCase('missing firewall blocks cloud before routing', async () => {
      let routeCalls = 0;
      const service = createInvestigationService({
        routeInference: async () => {
          routeCalls += 1;
          return routeSuccess(
            makeReport(),
            INFERENCE_SOURCES.IN_CLOUD,
            'mock-cloud-model'
          );
        },
      });
      const result = await service.investigateIncident(
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          incident: {
            incidentSummary: 'Incident summary.',
            evidence: TEST_EVIDENCE,
          },
        },
        { consentHandler: () => true }
      );
      assert(!result.ok && result.status === 'blocked', 'Missing firewall was not blocked.');
      assert(
        result.code === 'hybridRouter/privacy-firewall-unavailable' && routeCalls === 0,
        'Request reached routing without a firewall.'
      );
    })
  );

  cases.push(
    await runAsyncCase('denied cloud consent blocks execution', async () => {
      const observed = {};
      const service = createInvestigationService({
        routeInference: createCloudRouter({
          text: makeReport(),
          observed,
        }),
      });
      const result = await service.investigateIncident(
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          incident: {
            incidentSummary: 'Incident summary.',
            evidence: TEST_EVIDENCE,
          },
        },
        {
          privacyFirewall: createFirewall(
            {
              incidentSummary: 'Sanitized incident summary.',
              evidence: TEST_EVIDENCE,
            },
            observed
          ),
          consentHandler: () => false,
        }
      );
      assert(!result.ok && result.status === 'blocked', 'Denied consent was not blocked.');
      assert(result.code === 'hybridRouter/consent-denied', 'Consent failure code changed.');
    })
  );

  cases.push(
    await runAsyncCase('unavailable local AI remains unavailable', async () => {
      const service = createInvestigationService({
        routeInference: async () => ({
          ok: false,
          status: 'unavailable',
          inferenceSource: 'none',
          durationMs: 19,
          fallbackReason: 'localAI/unavailable',
          code: 'localAI/unavailable',
          message: 'Local model unavailable.',
        }),
      });
      const result = await service.investigateIncident({
        mode: OPERATING_MODES.PRIVATE_AI,
        incident: {
          incidentSummary: 'Private incident.',
          evidence: TEST_EVIDENCE,
        },
      });
      assert(!result.ok && result.status === 'unavailable', 'Unavailable private AI was fabricated as success.');
      assert(result.inferenceSource === 'none', 'Unavailable inference source was changed.');
      assert(result.fallbackReason === 'localAI/unavailable', 'Fallback reason was lost.');
    })
  );

  cases.push(
    await runAsyncCase('invalid AI response is rejected', async () => {
      const service = createInvestigationService({
        routeInference: async () => routeSuccess('not json'),
      });
      const result = await service.investigateIncident({
        mode: OPERATING_MODES.PRIVATE_AI,
        incident: {
          incidentSummary: 'Private incident.',
          evidence: TEST_EVIDENCE,
        },
      });
      assert(!result.ok && result.status === 'invalid_response', 'Malformed model output was accepted.');
      assert(
        result.inferenceSource === INFERENCE_SOURCES.ON_DEVICE,
        'Actual inference source was not preserved.'
      );
      assert(result.report === null, 'Invalid output returned a report.');
    })
  );

  cases.push(
    await runAsyncCase('unsupported evidence references are rejected', async () => {
      const service = createInvestigationService({
        routeInference: async () =>
          routeSuccess(makeReport({ evidenceId: 'E-UNKNOWN' })),
      });
      const result = await service.investigateIncident({
        mode: OPERATING_MODES.PRIVATE_AI,
        incident: {
          incidentSummary: 'Private incident.',
          evidence: TEST_EVIDENCE,
        },
      });
      assert(!result.ok && result.status === 'invalid_response', 'Unsupported evidence reference was accepted.');
      assert(result.code === 'prompts/unsupported-evidence-reference', 'Evidence validation code changed.');
    })
  );

  cases.push(
    await runAsyncCase('unapproved NVD query never reaches fetch or AI', async () => {
      const observed = {};
      const nvd = createNvdService(observed);
      const service = createInvestigationService({
        lookupCve: nvd.lookupCve,
        routeInference: async () => {
          observed.routeCalls = (observed.routeCalls ?? 0) + 1;
          return routeSuccess(
            makeReport(),
            INFERENCE_SOURCES.IN_CLOUD,
            'mock-cloud-model'
          );
        },
      });
      const result = await service.investigateIncident(
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          incident: {
            incidentSummary: 'Incident summary.',
            evidence: TEST_EVIDENCE,
          },
          vulnerabilityIds: [TEST_CVE_ID],
        },
        {
          privacyFirewall: createFirewall(
            {
              incidentSummary: 'Sanitized incident summary.',
              evidence: TEST_EVIDENCE,
            },
            observed
          ),
          consentHandler: () => true,
          approveNvdQuery: () => false,
        }
      );
      assert(!result.ok && result.status === 'blocked', 'Unapproved NVD lookup was not blocked.');
      assert(result.code === 'threatIntel/approval-denied', 'NVD approval failure code changed.');
      assert(observed.fetchCalls === undefined && observed.routeCalls === undefined, 'Unapproved query reached a network mock or AI router.');
    })
  );

  cases.push(
    await runAsyncCase('Essential Security returns deterministic rule analysis only', async () => {
      let observedPayload;
      const service = createInvestigationService({
        routeInference: async (payload, options) => {
          observedPayload = payload;
          assert(options.mode === OPERATING_MODES.ESSENTIAL_SECURITY, 'Essential Security mode changed.');
          return {
            ok: true,
            status: 'success',
            selectedMode: options.mode,
            inferenceSource: INFERENCE_SOURCES.RULE_ENGINE,
            model: null,
            durationMs: 7,
            fallbackReason: 'essential-security-deterministic-mode',
            text: makeReport(),
            ruleAnalysis: { summary: 'Deterministic rules identified an anomaly.' },
          };
        },
      });
      const result = await service.investigateIncident({
        mode: OPERATING_MODES.ESSENTIAL_SECURITY,
        incident: {
          incidentSummary: '',
          evidence: TEST_EVIDENCE,
          rawLogs: 'synthetic local rule-engine input',
        },
      });
      assert(
        result.ok &&
          result.inferenceSource === INFERENCE_SOURCES.RULE_ENGINE,
        'Rule engine result was not preserved.'
      );
      assert(result.report === null, 'Essential Security fabricated an AI report.');
      assert(
        result.ruleAnalysis.summary === 'Deterministic rules identified an anomaly.' &&
          observedPayload.rawLogs === 'synthetic local rule-engine input',
        'Rule-engine output or local input was lost.'
      );
    })
  );

  cases.push(
    await runAsyncCase('confidential incident data never reaches cloud route or executor', async () => {
      const observed = {};
      const service = createInvestigationService({
        routeInference: createCloudRouter({
          text: makeReport(),
          observed,
        }),
      });
      const result = await service.investigateIncident(
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          incident: {
            incidentSummary: 'Review this authentication event.',
            evidence: [
              { id: 'E-1', content: 'password=synthetic-secret' },
            ],
            rawLogs: 'credential=synthetic-secret',
            containsRawConfidentialData: true,
          },
        },
        {
          privacyFirewall: createFirewall(
            {
              incidentSummary: 'Review a sanitized authentication event.',
              evidence: [
                { id: 'E-1', content: 'Repeated authentication failures.' },
              ],
            },
            observed
          ),
          consentHandler: (_payload, context) =>
            context.sanitizedPrompt === observed.executorPrompt,
        }
      );
      assert(result.ok, 'Sanitized cloud investigation failed.');
      assert(
        !JSON.stringify(observed.routePayload).includes('synthetic-secret') &&
          !observed.executorPrompt.includes('synthetic-secret'),
        'Confidential canary data reached a cloud-capable route or executor.'
      );
      assert(
        observed.firewallInputs[0].prompt.includes('synthetic-secret'),
        'Test did not verify the local firewall received the raw canary.'
      );
    })
  );

  const passed = cases.filter((test) => test.passed).length;
  const failed = cases.length - passed;
  return {
    ok: failed === 0,
    status: failed === 0 ? 'passed' : 'failed',
    passed,
    failed,
    total: cases.length,
    results: cases,
  };
}

if (import.meta.env.DEV && !import.meta.env.PROD && typeof window !== 'undefined') {
  window.__veiltraceInvestigationServiceTest = runInvestigationServiceDevTest;
}
