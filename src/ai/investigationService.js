import {
  INFERENCE_SOURCES,
  OPERATING_MODES,
  routeInference,
} from './hybridRouter.js';
import {
  buildCloudAssistedInvestigationPrompt,
  buildPrivateInvestigationPrompt,
  parseInvestigationReport,
  PromptValidationError,
} from './prompts.js';
import { lookupCve } from './threatIntelligence.js';

const MAX_INCIDENT_JSON_CHARS = 80_000;
const MAX_VULNERABILITY_IDS = 10;
const CVE_ID_PATTERN = /^CVE-(\d{4})-(\d{4,})$/i;

const REQUEST_KEYS = ['mode', 'incident', 'vulnerabilityIds'];
const INCIDENT_KEYS = [
  'incidentSummary',
  'evidence',
  'rawLogs',
  'classification',
  'containsRawConfidentialData',
];
const OPTIONS_KEYS = [
  'privacyFirewall',
  'consentHandler',
  'ruleEngine',
  'approveNvdQuery',
  'signal',
  'model',
  'systemInstruction',
  'generationConfig',
  'onDeviceParams',
  'timeoutMs',
  'onDownloadProgress',
];

function getNowMs() {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function readRecord(value, label, allowedKeys) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    fail('investigation/invalid-request', `${label} must be a plain object.`);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    fail('investigation/invalid-request', `${label} must not contain symbol properties.`);
  }

  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = {};
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key];
    if (
      !allowedKeys.includes(key) ||
      !descriptor.enumerable ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    ) {
      fail('investigation/invalid-request', `${label} contains an unsupported property.`);
    }
    Object.defineProperty(result, key, {
      value: descriptor.value,
      enumerable: true,
    });
  }
  return result;
}

function cloneJson(value, state = { active: new WeakSet(), chars: 0 }, depth = 0) {
  if (depth > 12) {
    fail('investigation/invalid-request', 'Incident data exceeds the nesting limit.');
  }
  if (typeof value === 'string') {
    state.chars += value.length;
    if (state.chars > MAX_INCIDENT_JSON_CHARS) {
      fail('investigation/incident-too-large', 'Incident data exceeds the size limit.');
    }
    return value;
  }
  if (value === null || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value !== 'object' || state.active.has(value)) {
    fail(
      'investigation/invalid-request',
      'Incident data must contain finite, acyclic JSON-compatible values.'
    );
  }

  state.active.add(value);
  let cloned;
  if (Array.isArray(value)) {
    if (value.length > 1_000) {
      fail('investigation/incident-too-large', 'Incident arrays exceed the size limit.');
    }
    cloned = value.map((item) => cloneJson(item, state, depth + 1));
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail('investigation/invalid-request', 'Incident objects must be plain JSON data.');
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      fail('investigation/invalid-request', 'Incident data must not contain symbol properties.');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Object.keys(descriptors);
    if (keys.length > 200) {
      fail('investigation/incident-too-large', 'Incident objects exceed the field limit.');
    }
    cloned = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (
        key === '__proto__' ||
        key === 'constructor' ||
        key === 'prototype' ||
        !descriptor.enumerable ||
        !Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ) {
        fail('investigation/invalid-request', 'Incident data contains an unsafe property.');
      }
      Object.defineProperty(cloned, key, {
        value: cloneJson(descriptor.value, state, depth + 1),
        enumerable: true,
      });
    }
  }
  state.active.delete(value);
  return cloned;
}

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const child of Object.values(value)) {
    deepFreeze(child);
  }
  return value;
}

function normalizeRequest(request) {
  const record = readRecord(request, 'Investigation request', REQUEST_KEYS);
  const mode = record.mode ?? OPERATING_MODES.PRIVATE_AI;
  if (!Object.values(OPERATING_MODES).includes(mode)) {
    fail('investigation/invalid-mode', 'Select a supported investigation mode.');
  }

  const incidentRecord = readRecord(record.incident, 'Incident', INCIDENT_KEYS);
  const incidentSummary = incidentRecord.incidentSummary ?? '';
  if (typeof incidentSummary !== 'string') {
    fail('investigation/invalid-request', 'Incident summary must be text.');
  }
  const evidence = incidentRecord.evidence ?? [];
  const rawLogs =
    incidentRecord.rawLogs === undefined
      ? undefined
      : cloneJson(incidentRecord.rawLogs);
  const classification =
    incidentRecord.classification === undefined
      ? undefined
      : incidentRecord.classification;
  if (
    classification !== undefined &&
    (typeof classification !== 'string' || classification.length > 64)
  ) {
    fail('investigation/invalid-request', 'Incident classification is invalid.');
  }
  const containsRawConfidentialData =
    incidentRecord.containsRawConfidentialData ?? false;
  if (typeof containsRawConfidentialData !== 'boolean') {
    fail(
      'investigation/invalid-request',
      'containsRawConfidentialData must be a boolean.'
    );
  }

  const normalizedIncident = {
    incidentSummary,
    evidence: cloneJson(evidence),
    ...(rawLogs === undefined ? {} : { rawLogs }),
    ...(classification === undefined ? {} : { classification }),
    containsRawConfidentialData,
  };
  const serializedIncident = JSON.stringify(normalizedIncident);
  if (serializedIncident.length > MAX_INCIDENT_JSON_CHARS) {
    fail('investigation/incident-too-large', 'Incident data exceeds the size limit.');
  }

  const vulnerabilityIds = record.vulnerabilityIds ?? [];
  if (
    !Array.isArray(vulnerabilityIds) ||
    vulnerabilityIds.length > MAX_VULNERABILITY_IDS
  ) {
    fail(
      'investigation/invalid-vulnerability-list',
      `Provide at most ${MAX_VULNERABILITY_IDS} CVE identifiers.`
    );
  }
  const normalizedVulnerabilityIds = vulnerabilityIds.map((value) => {
    if (typeof value !== 'string' || !CVE_ID_PATTERN.test(value)) {
      fail(
        'investigation/invalid-vulnerability-list',
        'Vulnerability lookups require valid public CVE identifiers.'
      );
    }
    return value.toUpperCase();
  });
  if (new Set(normalizedVulnerabilityIds).size !== normalizedVulnerabilityIds.length) {
    fail(
      'investigation/invalid-vulnerability-list',
      'Vulnerability identifiers must not contain duplicates.'
    );
  }
  if (
    mode !== OPERATING_MODES.CLOUD_ASSISTED_AI &&
    normalizedVulnerabilityIds.length > 0
  ) {
    fail(
      'investigation/nvd-mode-prohibited',
      'External NVD lookups are available only in CLOUD_ASSISTED_AI mode.'
    );
  }

  return {
    mode,
    incident: normalizedIncident,
    vulnerabilityIds: normalizedVulnerabilityIds,
  };
}

function getFirewallValidator(firewall) {
  if (typeof firewall?.validateCloudPayload === 'function') {
    return firewall.validateCloudPayload.bind(firewall);
  }
  if (typeof firewall?.validate === 'function') {
    return firewall.validate.bind(firewall);
  }
  return null;
}

function normalizeSanitizedIncident(sanitizedPrompt, originalEvidence) {
  if (
    typeof sanitizedPrompt !== 'string' ||
    sanitizedPrompt.length === 0 ||
    sanitizedPrompt.length > MAX_INCIDENT_JSON_CHARS
  ) {
    fail(
      'investigation/firewall-output-invalid',
      'Privacy firewall must return a bounded sanitized incident JSON envelope.'
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(sanitizedPrompt);
  } catch {
    const evidenceIds = originalEvidence
      .map((item) => item?.id)
      .filter(
        (id) => typeof id === 'string' && sanitizedPrompt.includes(id)
      );
    buildPrivateInvestigationPrompt({
      incidentSummary: sanitizedPrompt,
      evidence: [],
    });
    return {
      incidentSummary: sanitizedPrompt,
      evidence: [],
      evidenceIds: [...new Set(evidenceIds)],
    };
  }
  const record = readRecord(
    parsed,
    'Sanitized incident',
    ['incidentSummary', 'evidence']
  );
  if (typeof record.incidentSummary !== 'string' || !Array.isArray(record.evidence)) {
    fail(
      'investigation/firewall-output-invalid',
      'Privacy firewall output must contain a summary and evidence array.'
    );
  }

  const sanitizedEvidence = record.evidence;
  const originalIds = new Set(
    originalEvidence.map((item) => item?.id).filter((id) => typeof id === 'string')
  );
  for (const item of sanitizedEvidence) {
    if (!item || typeof item.id !== 'string' || !originalIds.has(item.id)) {
      fail(
        'investigation/firewall-output-invalid',
        'Privacy firewall may preserve or remove evidence IDs but cannot add or change them.'
      );
    }
  }

  buildPrivateInvestigationPrompt({
    incidentSummary: record.incidentSummary,
    evidence: sanitizedEvidence,
  });
  return {
    incidentSummary: record.incidentSummary,
    evidence: sanitizedEvidence,
    evidenceIds: sanitizedEvidence.map((item) => item.id),
  };
}

async function validateAndSanitizeIncident(incident, firewall) {
  const validate = getFirewallValidator(firewall);
  if (!validate) {
    return {
      ok: false,
      code: 'hybridRouter/privacy-firewall-unavailable',
      message: 'A privacy firewall is required before cloud prompt construction.',
    };
  }

  const rawIncidentData = {
    incidentSummary: incident.incidentSummary,
    evidence: incident.evidence,
    ...(incident.rawLogs === undefined ? {} : { rawLogs: incident.rawLogs }),
  };
  const firewallPayload = deepFreeze({
    prompt: JSON.stringify(rawIncidentData),
    classification: incident.classification ?? 'untrusted',
    containsRawConfidentialData:
      incident.containsRawConfidentialData || incident.rawLogs !== undefined,
    sanitized: false,
  });

  let result;
  try {
    result = await validate(firewallPayload);
  } catch (error) {
    return {
      ok: false,
      code: 'hybridRouter/privacy-firewall-failed',
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'Privacy firewall validation failed.',
    };
  }
  if (result?.allowed !== true) {
    return {
      ok: false,
      code: result?.code ?? 'hybridRouter/privacy-firewall-rejected',
      message: result?.reason ?? 'Privacy firewall rejected the incident.',
    };
  }

  try {
    return {
      ok: true,
      incident: normalizeSanitizedIncident(
        result.sanitizedPrompt,
        incident.evidence
      ),
    };
  } catch (error) {
    return {
      ok: false,
      code:
        typeof error?.code === 'string'
          ? error.code
          : 'investigation/firewall-output-invalid',
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'Privacy firewall returned invalid sanitized data.',
    };
  }
}

function createExactPromptFirewall(firewall, finalPrompt) {
  const validate = getFirewallValidator(firewall);
  return {
    async validateCloudPayload(payload) {
      const result = await validate(payload);
      if (result?.allowed !== true) {
        return result;
      }
      if (
        payload?.prompt !== finalPrompt ||
        typeof result.sanitizedPrompt !== 'string' ||
        result.sanitizedPrompt.trim() !== finalPrompt
      ) {
        return {
          allowed: false,
          code: 'investigation/final-prompt-changed',
          reason:
            'The router firewall must approve the exact final prompt without changing it.',
        };
      }
      return { ...result, sanitizedPrompt: finalPrompt };
    },
  };
}

function makeRouteOptions(mode, options) {
  return {
    mode,
    ...(options.privacyFirewall ? { privacyFirewall: options.privacyFirewall } : {}),
    ...(options.consentHandler ? { consentHandler: options.consentHandler } : {}),
    ...(options.ruleEngine ? { ruleEngine: options.ruleEngine } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.model ? { model: options.model } : {}),
    ...(options.systemInstruction
      ? { systemInstruction: options.systemInstruction }
      : {}),
    ...(options.generationConfig
      ? { generationConfig: options.generationConfig }
      : {}),
    ...(options.onDeviceParams
      ? { onDeviceParams: options.onDeviceParams }
      : {}),
    ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.onDownloadProgress
      ? { onDownloadProgress: options.onDownloadProgress }
      : {}),
  };
}

function metadataFromRoute(routeResult, mode, totalDurationMs) {
  return {
    selectedMode: mode,
    inferenceSource: routeResult?.inferenceSource ?? INFERENCE_SOURCES.NONE,
    model: routeResult?.model ?? null,
    status: routeResult?.status ?? 'error',
    durationMs:
      Number.isFinite(routeResult?.durationMs) && routeResult.durationMs >= 0
        ? routeResult.durationMs
        : totalDurationMs,
    totalDurationMs,
    fallbackReason: routeResult?.fallbackReason ?? null,
  };
}

function failureResult({
  status,
  mode,
  code,
  message,
  durationMs,
  inferenceSource = INFERENCE_SOURCES.NONE,
  model = null,
  fallbackReason = code,
  vulnerabilityIntelligence = [],
}) {
  return {
    ok: false,
    status,
    selectedMode: mode ?? null,
    inferenceSource,
    model,
    durationMs,
    totalDurationMs: durationMs,
    fallbackReason,
    code,
    message,
    report: null,
    ruleAnalysis: null,
    vulnerabilityIntelligence,
  };
}

function mapThreatIntelligenceError(error, mode, durationMs) {
  const code =
    typeof error?.code === 'string'
      ? error.code
      : 'threatIntel/lookup-failed';
  const approvalFailure =
    code.includes('approval') || code === 'threatIntel/client-rate-limited';
  return failureResult({
    status: approvalFailure ? 'blocked' : 'unavailable',
    mode,
    code,
    message:
      typeof error?.message === 'string'
        ? error.message
        : 'Threat intelligence lookup failed.',
    durationMs,
  });
}

function attachVulnerabilityProvenance(report, intelligence) {
  const records = new Map(
    intelligence.map((record) => [record.cveId, record])
  );
  return {
    ...report,
    relevantVulnerabilities: report.relevantVulnerabilities.map((entry) => {
      const source = records.get(entry.cveId);
      return {
        ...entry,
        cached: source?.cached ?? entry.source === 'cache',
        retrievedAt: source?.retrievedAt ?? null,
        sourceUrl: source?.sourceUrl ?? null,
      };
    }),
  };
}

function normalizeOptions(options) {
  return readRecord(options, 'Investigation options', OPTIONS_KEYS);
}

/**
 * Creates an investigation orchestrator. External dependencies can be injected
 * for deterministic tests; production defaults use the existing router and NVD
 * service interfaces.
 *
 * The cloud firewall contract is the existing `{ allowed, sanitizedPrompt }`
 * shape. Prefer JSON containing `{ incidentSummary, evidence }`; a plain
 * sanitized string is accepted as summary text, with only included original
 * evidence IDs retained for report validation.
 *
 * @param {{
 *   routeInference?: typeof routeInference,
 *   lookupCve?: typeof lookupCve
 * }} dependencies
 */
export function createInvestigationService(dependencies = {}) {
  const route = dependencies.routeInference ?? routeInference;
  const lookup = dependencies.lookupCve ?? lookupCve;

  /**
   * @param {{
   *   mode?: 'PRIVATE_AI' | 'CLOUD_ASSISTED_AI' | 'ESSENTIAL_SECURITY',
   *   incident: object,
   *   vulnerabilityIds?: string[]
   * }} request
   * @param {{
   *   privacyFirewall?: object,
   *   consentHandler?: Function,
   *   ruleEngine?: object,
   *   approveNvdQuery?: Function,
   *   signal?: AbortSignal
   * }} options
   */
  async function investigateIncident(request, options = {}) {
    const startedAt = getNowMs();
    let normalized;
    let normalizedOptions;
    try {
      normalized = normalizeRequest(request);
      normalizedOptions = normalizeOptions(options);
    } catch (error) {
      const durationMs = Math.round(getNowMs() - startedAt);
      return failureResult({
        status: 'invalid_request',
        mode: request?.mode ?? null,
        code:
          typeof error?.code === 'string'
            ? error.code
            : 'investigation/invalid-request',
        message:
          typeof error?.message === 'string'
            ? error.message
            : 'Investigation request is invalid.',
        durationMs,
      });
    }

    const { mode, incident, vulnerabilityIds } = normalized;

    if (mode === OPERATING_MODES.ESSENTIAL_SECURITY) {
      const essentialPayload = {
        ...incident,
        prompt:
          incident.incidentSummary ||
          'Run deterministic Essential Security analysis on the supplied incident.',
      };
      return executeAndNormalize({
        route,
        mode,
        payload: essentialPayload,
        routeOptions: makeRouteOptions(mode, normalizedOptions),
        evidenceIds: [],
        approvedNvdIntelligence: [],
        vulnerabilityIntelligence: [],
        startedAt,
      });
    }

    if (mode === OPERATING_MODES.PRIVATE_AI) {
      let prompt;
      try {
        prompt = buildPrivateInvestigationPrompt({
          incidentSummary: incident.incidentSummary,
          evidence: incident.evidence,
        });
      } catch (error) {
        return failureResult({
          status: 'invalid_request',
          mode,
          code:
            typeof error?.code === 'string'
              ? error.code
              : 'prompts/invalid-input',
          message:
            typeof error?.message === 'string'
              ? error.message
              : 'Private investigation input is invalid.',
          durationMs: Math.round(getNowMs() - startedAt),
        });
      }

      const evidenceIds = incident.evidence.map((entry) => entry.id);
      return executeAndNormalize({
        route,
        mode,
        payload: { ...incident, prompt },
        routeOptions: makeRouteOptions(mode, normalizedOptions),
        evidenceIds,
        approvedNvdIntelligence: [],
        vulnerabilityIntelligence: [],
        startedAt,
      });
    }

    const firewall = normalizedOptions.privacyFirewall;
    const consentHandler = normalizedOptions.consentHandler;
    if (!getFirewallValidator(firewall)) {
      return failureResult({
        status: 'blocked',
        mode,
        code: 'hybridRouter/privacy-firewall-unavailable',
        message: 'A privacy firewall is required before cloud prompt construction.',
        durationMs: Math.round(getNowMs() - startedAt),
      });
    }
    if (typeof consentHandler !== 'function') {
      return failureResult({
        status: 'blocked',
        mode,
        code: 'hybridRouter/consent-handler-unavailable',
        message: 'A fresh explicit consent handler is required for cloud inference.',
        durationMs: Math.round(getNowMs() - startedAt),
      });
    }
    if (vulnerabilityIds.length > 0 && typeof normalizedOptions.approveNvdQuery !== 'function') {
      return failureResult({
        status: 'blocked',
        mode,
        code: 'threatIntel/approval-required',
        message: 'Separate explicit approval is required for each external NVD query.',
        durationMs: Math.round(getNowMs() - startedAt),
      });
    }

    try {
      buildPrivateInvestigationPrompt({
        incidentSummary: incident.incidentSummary,
        evidence: incident.evidence,
      });
    } catch (error) {
      return failureResult({
        status: 'invalid_request',
        mode,
        code:
          typeof error?.code === 'string'
            ? error.code
            : 'prompts/invalid-input',
        message:
          typeof error?.message === 'string'
            ? error.message
            : 'Incident evidence is invalid.',
        durationMs: Math.round(getNowMs() - startedAt),
      });
    }

    const sanitizedResult = await validateAndSanitizeIncident(incident, firewall);
    if (!sanitizedResult.ok) {
      return failureResult({
        status: 'blocked',
        mode,
        code: sanitizedResult.code,
        message: sanitizedResult.message,
        durationMs: Math.round(getNowMs() - startedAt),
      });
    }

    const vulnerabilityIntelligence = [];
    for (const cveId of vulnerabilityIds) {
      try {
        const record = await lookup(cveId, {
          approveQuery: normalizedOptions.approveNvdQuery,
          signal: normalizedOptions.signal,
        });
        vulnerabilityIntelligence.push({ ...record, approved: true });
      } catch (error) {
        return mapThreatIntelligenceError(
          error,
          mode,
          Math.round(getNowMs() - startedAt)
        );
      }
    }

    let cloudPrompt;
    try {
      cloudPrompt = buildCloudAssistedInvestigationPrompt({
        sanitized: true,
        incidentSummary: sanitizedResult.incident.incidentSummary,
        evidence: sanitizedResult.incident.evidence,
        approvedNvdIntelligence: vulnerabilityIntelligence,
      });
    } catch (error) {
      return failureResult({
        status: 'blocked',
        mode,
        code:
          typeof error?.code === 'string'
            ? error.code
            : 'investigation/sanitized-input-rejected',
        message:
          typeof error?.message === 'string'
            ? error.message
            : 'Sanitized incident information was rejected.',
        durationMs: Math.round(getNowMs() - startedAt),
        vulnerabilityIntelligence,
      });
    }

    return executeAndNormalize({
      route,
      mode,
      payload: {
        prompt: cloudPrompt,
        sanitized: true,
        classification: 'sanitized',
        containsRawConfidentialData: false,
      },
      routeOptions: makeRouteOptions(mode, {
        ...normalizedOptions,
        privacyFirewall: createExactPromptFirewall(firewall, cloudPrompt),
      }),
      evidenceIds: sanitizedResult.incident.evidenceIds,
      approvedNvdIntelligence: vulnerabilityIntelligence,
      vulnerabilityIntelligence,
      startedAt,
    });
  }

  return { investigateIncident };
}

async function executeAndNormalize({
  route,
  mode,
  payload,
  routeOptions,
  evidenceIds,
  approvedNvdIntelligence,
  vulnerabilityIntelligence,
  startedAt,
}) {
  let routeResult;
  try {
    routeResult = await route(payload, routeOptions);
  } catch (error) {
    const durationMs = Math.round(getNowMs() - startedAt);
    return failureResult({
      status: 'error',
      mode,
      code:
        typeof error?.code === 'string'
          ? error.code
          : 'hybridRouter/inference-failed',
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'Hybrid router execution failed.',
      durationMs,
      vulnerabilityIntelligence,
    });
  }

  const totalDurationMs = Math.round(getNowMs() - startedAt);
  const metadata = metadataFromRoute(routeResult, mode, totalDurationMs);
  if (!routeResult?.ok) {
    return {
      ...failureResult({
        status:
          routeResult?.status === 'blocked' ||
          routeResult?.status === 'unavailable' ||
          routeResult?.status === 'rejected'
            ? routeResult.status
            : 'error',
        mode,
        code: routeResult?.code ?? 'hybridRouter/inference-failed',
        message: routeResult?.message ?? 'Hybrid router did not complete inference.',
        durationMs: metadata.durationMs,
        inferenceSource: metadata.inferenceSource,
        model: metadata.model,
        fallbackReason: metadata.fallbackReason,
        vulnerabilityIntelligence,
      }),
      totalDurationMs,
    };
  }

  if (mode === OPERATING_MODES.ESSENTIAL_SECURITY) {
    if (metadata.inferenceSource !== INFERENCE_SOURCES.RULE_ENGINE) {
      return failureResult({
        status: 'blocked',
        mode,
        code: 'investigation/essential-security-ai-source-blocked',
        message: 'Essential Security mode accepts deterministic rule-engine results only.',
        durationMs: metadata.durationMs,
        inferenceSource: metadata.inferenceSource,
        model: metadata.model,
        fallbackReason: metadata.fallbackReason,
      });
    }
    return {
      ok: true,
      ...metadata,
      report: null,
      ruleAnalysis: routeResult.ruleAnalysis ?? null,
      vulnerabilityIntelligence: [],
    };
  }

  if (metadata.inferenceSource === INFERENCE_SOURCES.RULE_ENGINE) {
    return {
      ok: true,
      ...metadata,
      report: null,
      ruleAnalysis: routeResult.ruleAnalysis ?? null,
      vulnerabilityIntelligence,
    };
  }

  if (
    mode === OPERATING_MODES.PRIVATE_AI &&
    metadata.inferenceSource === INFERENCE_SOURCES.IN_CLOUD
  ) {
    return failureResult({
      status: 'blocked',
      mode,
      code: 'investigation/private-cloud-source-blocked',
      message: 'Private AI mode cannot accept cloud inference results.',
      durationMs: metadata.durationMs,
      inferenceSource: metadata.inferenceSource,
      model: metadata.model,
      fallbackReason: metadata.fallbackReason,
    });
  }

  if (
    metadata.inferenceSource !== INFERENCE_SOURCES.ON_DEVICE &&
    metadata.inferenceSource !== INFERENCE_SOURCES.IN_CLOUD
  ) {
    return failureResult({
      status: 'unavailable',
      mode,
      code: 'investigation/inference-source-unavailable',
      message: 'The router returned no recognized AI inference source.',
      durationMs: metadata.durationMs,
      inferenceSource: metadata.inferenceSource,
      model: metadata.model,
      fallbackReason: metadata.fallbackReason,
      vulnerabilityIntelligence,
    });
  }

  let report;
  try {
    report = parseInvestigationReport(routeResult.text, {
      evidenceIds,
      approvedNvdIntelligence,
    });
  } catch (error) {
    return failureResult({
      status: 'invalid_response',
      mode,
      code:
        error instanceof PromptValidationError
          ? error.code
          : 'prompts/malformed-report',
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'AI response failed investigation report validation.',
      durationMs: metadata.durationMs,
      inferenceSource: metadata.inferenceSource,
      model: metadata.model,
      fallbackReason: metadata.fallbackReason,
      vulnerabilityIntelligence,
    });
  }

  return {
    ok: true,
    ...metadata,
    report: attachVulnerabilityProvenance(report, vulnerabilityIntelligence),
    ruleAnalysis: null,
    vulnerabilityIntelligence,
  };
}

const defaultService = createInvestigationService();

export const investigateIncident = (request, options) =>
  defaultService.investigateIncident(request, options);

export { INFERENCE_SOURCES, OPERATING_MODES };
