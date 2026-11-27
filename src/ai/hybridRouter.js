import {
  getAI,
  getGenerativeModel,
  GoogleAIBackend,
  InferenceMode,
  InferenceSource,
  ThinkingLevel,
} from 'firebase/ai';
import { app } from './firebase';
import { initAppCheck } from './appCheck';
import { DEFAULT_CLOUD_MODEL, DEFAULT_TIMEOUT_MS } from './cloudAI';
import {
  DEFAULT_ON_DEVICE_CREATE_OPTIONS,
  detectLocalAIAvailability,
  generateLocalResponse,
} from './localAI';

export const OPERATING_MODES = Object.freeze({
  PRIVATE_AI: 'PRIVATE_AI',
  CLOUD_ASSISTED_AI: 'CLOUD_ASSISTED_AI',
  ESSENTIAL_SECURITY: 'ESSENTIAL_SECURITY',
});

export const INFERENCE_SOURCES = Object.freeze({
  ON_DEVICE: InferenceSource.ON_DEVICE,
  IN_CLOUD: InferenceSource.IN_CLOUD,
  RULE_ENGINE: 'rule_engine',
  NONE: 'none',
});

const HYBRID_AI_GLOBAL_KEY = Symbol.for('veiltrace.firebase.hybridAI');
const RAW_OR_CONFIDENTIAL_CLASSIFICATIONS = new Set([
  'raw',
  'confidential',
  'restricted',
  'pii',
  'secret',
]);

let registeredPrivacyFirewall = null;
let registeredRuleEngine = null;
let registeredConsentHandler = null;

function getNowMs() {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

/**
 * Registers the security engine's privacy firewall validator.
 * Must expose `validateCloudPayload(payload)` (or `validate(payload)`) returning
 * `{ allowed: true, sanitizedPrompt: string }` for approved sanitized data.
 *
 * @param {{ validateCloudPayload?: Function, validate?: Function } | null} firewall
 */
export function registerPrivacyFirewall(firewall) {
  const previous = registeredPrivacyFirewall;
  registeredPrivacyFirewall = firewall ?? null;
  return createRegistrationRestore(
    () => registeredPrivacyFirewall,
    (value) => {
      registeredPrivacyFirewall = value;
    },
    registeredPrivacyFirewall,
    previous
  );
}

/**
 * Registers the security engine's deterministic rule-based fallback analyzer.
 * Must expose `analyze(payload, context)`.
 *
 * @param {{ analyze: Function } | null} engine
 */
export function registerRuleEngine(engine) {
  const previous = registeredRuleEngine;
  registeredRuleEngine = engine ?? null;
  return createRegistrationRestore(
    () => registeredRuleEngine,
    (value) => {
      registeredRuleEngine = value;
    },
    registeredRuleEngine,
    previous
  );
}

/**
 * Registers the per-request consent handler for cloud-capable inference.
 *
 * @param {Function | null} handler
 * @returns {() => void}
 */
export function registerConsentHandler(handler) {
  const previous = registeredConsentHandler;
  registeredConsentHandler = typeof handler === 'function' ? handler : null;
  return createRegistrationRestore(
    () => registeredConsentHandler,
    (value) => {
      registeredConsentHandler = value;
    },
    registeredConsentHandler,
    previous
  );
}

function createRegistrationRestore(getCurrent, setCurrent, registered, previous) {
  let restored = false;
  return () => {
    if (!restored && getCurrent() === registered) {
      setCurrent(previous);
    }
    restored = true;
  };
}

function getActivePrivacyFirewall(overrideFirewall) {
  const candidate = overrideFirewall ?? registeredPrivacyFirewall;
  if (
    candidate &&
    (typeof candidate.validateCloudPayload === 'function' ||
      typeof candidate.validate === 'function')
  ) {
    return candidate;
  }
  return null;
}

function getActiveRuleEngine(overrideEngine) {
  const candidate = overrideEngine ?? registeredRuleEngine;
  if (candidate && typeof candidate.analyze === 'function') {
    return candidate;
  }
  return null;
}

function detectNetworkAvailability() {
  if (typeof navigator === 'undefined') {
    return { online: false, source: 'non-browser' };
  }
  return {
    online: navigator.onLine !== false,
    source: 'navigator.onLine',
  };
}

/**
 * Reports real local AI, network, privacy firewall, and rule-engine capabilities.
 *
 * @param {{ privacyFirewall?: object, ruleEngine?: object }} [options]
 */
export async function detectHybridCapabilities(options = {}) {
  const localAI = await detectLocalAIAvailability();
  const network = detectNetworkAvailability();
  const privacyFirewallAvailable = Boolean(
    getActivePrivacyFirewall(options.privacyFirewall)
  );
  const ruleEngineAvailable = Boolean(getActiveRuleEngine(options.ruleEngine));

  return {
    localAI,
    network,
    privacyFirewallAvailable,
    ruleEngineAvailable,
  };
}

function getHybridFirebaseAI() {
  const appCheckInstance = initAppCheck();
  if (!appCheckInstance) {
    const err = new Error(
      'Firebase App Check must be initialized before hybrid cloud inference.'
    );
    err.code = 'hybridRouter/app-check-not-initialized';
    throw err;
  }

  const existing = globalThis[HYBRID_AI_GLOBAL_KEY];
  if (existing && existing.app === app) {
    return existing;
  }

  const ai = getAI(app, {
    backend: new GoogleAIBackend(),
    useLimitedUseAppCheckTokens: true,
  });

  globalThis[HYBRID_AI_GLOBAL_KEY] = ai;
  return ai;
}

function validateBasePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      valid: false,
      code: 'hybridRouter/invalid-payload',
      reason: 'Payload must be a non-null object.',
    };
  }

  if (typeof payload.prompt !== 'string' || payload.prompt.trim().length === 0) {
    return {
      valid: false,
      code: 'hybridRouter/invalid-payload',
      reason: 'Payload prompt must be a non-empty string.',
    };
  }

  return { valid: true };
}

function clonePlainData(value, active = new WeakSet()) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  ) {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value !== 'object' || active.has(value)) {
    throw new TypeError('Payload must contain finite JSON-compatible data.');
  }

  active.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new TypeError('Payload must not contain array subclasses.');
      }

      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Object.getOwnPropertySymbols(value).length > 0) {
        throw new TypeError('Payload must not contain symbol properties.');
      }

      const clone = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[index];
        if (
          !descriptor ||
          !descriptor.enumerable ||
          !Object.prototype.hasOwnProperty.call(descriptor, 'value')
        ) {
          throw new TypeError('Payload arrays must contain plain data values.');
        }
        clone.push(clonePlainData(descriptor.value, active));
      }
      if (
        Object.keys(descriptors).some(
          (key) =>
            key !== 'length' &&
            (!/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length)
        )
      ) {
        throw new TypeError('Payload arrays must not contain extra properties.');
      }
      return clone;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('Payload must contain only plain objects.');
    }

    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new TypeError('Payload must not contain symbol properties.');
    }

    const clone = {};
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key];
      if (
        !descriptor.enumerable ||
        !Object.prototype.hasOwnProperty.call(descriptor, 'value')
      ) {
        throw new TypeError('Payload must not contain accessors or hidden properties.');
      }
      if (['__proto__', 'prototype', 'constructor'].includes(key)) {
        throw new TypeError('Payload contains a disallowed property name.');
      }
      Object.defineProperty(clone, key, {
        value: clonePlainData(descriptor.value, active),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return clone;
  } finally {
    active.delete(value);
  }
}

function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) {
      freezeDeep(child);
    }
  }
  return value;
}

function capturePayload(payload) {
  try {
    const value = clonePlainData(payload);
    return {
      value,
      fingerprint: JSON.stringify(value),
    };
  } catch {
    return null;
  }
}

function containsSensitiveFieldsOrText(value) {
  if (typeof value === 'string') {
    return (
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i.test(value) ||
      /\bBearer\s+[A-Za-z0-9._~+/-]+=*/i.test(value) ||
      /\b(?:password|passwd|secret|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|client[_ -]?secret)\s*[:=]\s*\S+/i.test(
        value
      ) ||
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/.test(
        value
      ) ||
      /\bAKIA[0-9A-Z]{16}\b/.test(value) ||
      /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(value) ||
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(value) ||
      /\b\d{3}-\d{2}-\d{4}\b/.test(value)
    );
  }
  if (Array.isArray(value)) {
    return value.some(containsSensitiveFieldsOrText);
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([key, child]) => {
      const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      return (
        /^(?:raw)?logs?$/.test(normalizedKey) ||
        /^(?:passwords?|passwds?|secrets?|credentials?|authorization|apikeys?|accesskeys?|accesstokens?|refreshtokens?|clientsecrets?|privatekeys?)$/.test(
          normalizedKey
        ) ||
        containsSensitiveFieldsOrText(child)
      );
    });
  }
  return false;
}

/**
 * Strict fail-closed cloud authorization gate.
 * Prevents raw/confidential logs, missing consent, or missing privacy firewall
 * from ever reaching `InferenceMode.PREFER_ON_DEVICE` or any cloud-capable path.
 *
 * @param {object} payload
 * @param {object} options
 * @returns {Promise<{
 *   authorized: boolean,
 *   sanitizedPrompt?: string,
 *   cloudOptions?: object,
 *   code?: string,
 *   reason?: string
 * }>}
 */
async function authorizeCloudCapablePayload(
  payload,
  options,
  originalPayload,
  originalFingerprint
) {
  const captured = capturePayload(payload);
  if (!captured) {
    return {
      authorized: false,
      code: 'hybridRouter/invalid-payload',
      reason: 'Payload must be plain, immutable-compatible JSON data.',
    };
  }

  const snapshot = freezeDeep(captured.value);
  const classification =
    typeof snapshot.classification === 'string'
      ? snapshot.classification.trim().toLowerCase()
      : '';
  const cloudConfig = capturePayload({
    model: options.model ?? null,
    systemInstruction: options.systemInstruction ?? null,
    generationConfig: options.generationConfig ?? null,
  });

  if (!cloudConfig) {
    return {
      authorized: false,
      code: 'hybridRouter/invalid-cloud-options',
      reason: 'Cloud inference options must be plain JSON-compatible data.',
    };
  }

  if (
    snapshot.containsRawConfidentialData === true ||
    RAW_OR_CONFIDENTIAL_CLASSIFICATIONS.has(classification) ||
    snapshot.rawLogs != null ||
    containsSensitiveFieldsOrText(snapshot) ||
    containsSensitiveFieldsOrText(cloudConfig.value)
  ) {
    return {
      authorized: false,
      code: 'hybridRouter/raw-data-prohibited',
      reason: 'Raw or confidential data is strictly prohibited from cloud-capable paths.',
    };
  }

  if (snapshot.sanitized !== true) {
    return {
      authorized: false,
      code: 'hybridRouter/unsanitized-payload',
      reason: 'Payload must be explicitly sanitized before cloud-capable routing.',
    };
  }

  const firewall = getActivePrivacyFirewall(options.privacyFirewall);
  if (!firewall) {
    return {
      authorized: false,
      code: 'hybridRouter/privacy-firewall-unavailable',
      reason:
        'Security engine privacy firewall is not available; cloud routing is blocked by default.',
    };
  }

  const validateFn =
    typeof firewall.validateCloudPayload === 'function'
      ? firewall.validateCloudPayload.bind(firewall)
      : firewall.validate.bind(firewall);

  let firewallResult;
  try {
    firewallResult = await validateFn(snapshot);
  } catch (error) {
    return {
      authorized: false,
      code: 'hybridRouter/privacy-firewall-failed',
      reason:
        typeof error?.message === 'string'
          ? error.message
          : 'Privacy firewall validation failed.',
    };
  }
  const sanitizedPrompt =
    typeof firewallResult?.sanitizedPrompt === 'string'
      ? firewallResult.sanitizedPrompt.trim()
      : '';

  if (firewallResult?.allowed !== true || sanitizedPrompt.length === 0) {
    return {
      authorized: false,
      code: firewallResult?.code || 'hybridRouter/privacy-firewall-rejected',
      reason:
        firewallResult?.reason ||
        'Privacy firewall rejected payload for cloud-capable inference.',
    };
  }

  if (containsSensitiveFieldsOrText(sanitizedPrompt)) {
    return {
      authorized: false,
      code: 'hybridRouter/sensitive-output-blocked',
      reason: 'Privacy firewall output contains data marked as sensitive.',
    };
  }

  const currentPayload = capturePayload(originalPayload);
  if (!currentPayload || currentPayload.fingerprint !== originalFingerprint) {
    return {
      authorized: false,
      code: 'hybridRouter/payload-changed',
      reason: 'Payload changed while privacy validation was in progress.',
    };
  }

  const consentHandler =
    typeof options.consentHandler === 'function'
      ? options.consentHandler
      : registeredConsentHandler;
  if (!consentHandler) {
    return {
      authorized: false,
      code: 'hybridRouter/consent-handler-unavailable',
      reason: 'A fresh explicit consent handler is required for cloud inference.',
    };
  }

  let consentGranted;
  try {
    consentGranted = await consentHandler(snapshot, {
      sanitizedPrompt,
      payloadFingerprint: captured.fingerprint,
    });
  } catch (error) {
    return {
      authorized: false,
      code: 'hybridRouter/consent-failed',
      reason:
        typeof error?.message === 'string'
          ? error.message
          : 'Explicit consent could not be confirmed.',
    };
  }

  const consentedPayload = capturePayload(originalPayload);
  if (!consentedPayload || consentedPayload.fingerprint !== originalFingerprint) {
    return {
      authorized: false,
      code: 'hybridRouter/payload-changed',
      reason: 'Payload changed while explicit consent was being confirmed.',
    };
  }
  if (consentGranted !== true) {
    return {
      authorized: false,
      code: 'hybridRouter/consent-denied',
      reason: 'Explicit consent was not granted for this validated payload.',
    };
  }

  return {
    authorized: true,
    sanitizedPrompt,
    cloudOptions: freezeDeep(cloudConfig.value),
  };
}

/**
 * Default executor using the official Firebase AI Logic Hybrid SDK
 * (`InferenceMode.PREFER_ON_DEVICE`). Only invoked after cloud authorization succeeds.
 */
async function executePreferOnDeviceHybrid(sanitizedPrompt, options = {}) {
  const ai = getHybridFirebaseAI();
  const timeoutMs =
    typeof options.timeoutMs === 'number' && options.timeoutMs > 0
      ? options.timeoutMs
      : DEFAULT_TIMEOUT_MS;
  const selectedModel =
    typeof options.model === 'string' && options.model.trim().length > 0
      ? options.model.trim()
      : DEFAULT_CLOUD_MODEL;

  const userGenConfig = options.generationConfig
    ? { ...options.generationConfig }
    : {};
  if (
    userGenConfig.thinkingConfig?.thinkingLevel === undefined &&
    userGenConfig.thinkingConfig?.thinkingBudget === undefined
  ) {
    userGenConfig.thinkingConfig = {
      ...(userGenConfig.thinkingConfig ?? {}),
      thinkingLevel: ThinkingLevel.LOW,
    };
  }

  const generativeModel = getGenerativeModel(
    ai,
    {
      mode: InferenceMode.PREFER_ON_DEVICE,
      inCloudParams: {
        model: selectedModel,
        generationConfig: userGenConfig,
        ...(options.systemInstruction
          ? { systemInstruction: options.systemInstruction }
          : {}),
      },
      onDeviceParams: {
        ...(options.onDeviceParams ?? {}),
        createOptions: {
          ...DEFAULT_ON_DEVICE_CREATE_OPTIONS,
          ...(options.onDeviceParams?.createOptions ?? {}),
          ...(options.signal ? { signal: options.signal } : {}),
        },
      },
    },
    { timeout: timeoutMs }
  );

  const result = await generativeModel.generateContent(sanitizedPrompt, {
    timeout: timeoutMs,
    ...(options.signal ? { signal: options.signal } : {}),
  });

  const text = result?.response?.text?.()?.trim() ?? '';
  if (!text) {
    const err = new Error('Hybrid inference returned an empty response.');
    err.code = 'hybridRouter/empty-response';
    throw err;
  }

  const actualSource =
    result?.response?.inferenceSource ?? InferenceSource.IN_CLOUD;

  return {
    text,
    inferenceSource: actualSource,
    model:
      actualSource === InferenceSource.ON_DEVICE ? 'gemini-nano' : selectedModel,
  };
}

function getHybridExecutionOptions(options, cloudOptions) {
  return {
    ...(cloudOptions.model ? { model: cloudOptions.model } : {}),
    ...(cloudOptions.systemInstruction
      ? { systemInstruction: cloudOptions.systemInstruction }
      : {}),
    ...(cloudOptions.generationConfig
      ? { generationConfig: cloudOptions.generationConfig }
      : {}),
    ...(options.onDeviceParams
      ? { onDeviceParams: options.onDeviceParams }
      : {}),
    ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
  };
}

async function runRuleBasedFallback(
  payload,
  selectedMode,
  fallbackReason,
  startedAt,
  options
) {
  const ruleEngine = getActiveRuleEngine(options.ruleEngine);
  if (!ruleEngine) {
    return {
      ok: false,
      status: 'unavailable',
      selectedMode,
      inferenceSource: INFERENCE_SOURCES.NONE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason,
      code:
        selectedMode === OPERATING_MODES.ESSENTIAL_SECURITY
          ? 'hybridRouter/rule-engine-unavailable'
          : fallbackReason,
      text: null,
      ruleAnalysis: null,
    };
  }

  try {
    const analysis = await ruleEngine.analyze(payload, {
      selectedMode,
      fallbackReason,
    });

    return {
      ok: true,
      status:
        selectedMode === OPERATING_MODES.ESSENTIAL_SECURITY
          ? 'success'
          : 'fallback',
      selectedMode,
      inferenceSource: INFERENCE_SOURCES.RULE_ENGINE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason,
      text: typeof analysis?.summary === 'string' ? analysis.summary : null,
      ruleAnalysis: analysis ?? null,
    };
  } catch (error) {
    return {
      ok: false,
      status: 'error',
      selectedMode,
      inferenceSource: INFERENCE_SOURCES.NONE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason,
      code:
        typeof error?.code === 'string'
          ? error.code
          : 'hybridRouter/rule-engine-failed',
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'Rule-based fallback execution failed.',
      text: null,
      ruleAnalysis: null,
    };
  }
}

/**
 * Routes VeilTrace AI analysis requests according to operating mode and strict
 * fail-closed privacy guarantees.
 *
 * @param {{
 *   prompt: string,
 *   sanitized?: boolean,
 *   classification?: string,
 *   containsRawConfidentialData?: boolean,
 *   rawLogs?: unknown,
 *   userConsent?: boolean
 * }} payload
 * @param {{
 *   mode?: 'PRIVATE_AI' | 'CLOUD_ASSISTED_AI' | 'ESSENTIAL_SECURITY',
 *   userConsent?: boolean,
 *   consentHandler?: (payload: object, context: { sanitizedPrompt: string, payloadFingerprint: string }) => Promise<boolean> | boolean,
 *   privacyFirewall?: object,
 *   ruleEngine?: object,
 *   model?: string,
 *   systemInstruction?: string,
 *   generationConfig?: import('firebase/ai').GenerationConfig,
 *   onDeviceParams?: import('firebase/ai').OnDeviceParams,
 *   timeoutMs?: number,
 *   signal?: AbortSignal,
 *   onDownloadProgress?: (progress: number) => void,
 *   hybridExecutor?: Function
 * }} [options]
 */
export async function routeInference(payload, options = {}) {
  const startedAt = getNowMs();
  const selectedMode = options.mode ?? OPERATING_MODES.PRIVATE_AI;

  if (!Object.values(OPERATING_MODES).includes(selectedMode)) {
    return {
      ok: false,
      status: 'error',
      selectedMode: String(selectedMode),
      inferenceSource: INFERENCE_SOURCES.NONE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason: 'invalid-operating-mode',
      code: 'hybridRouter/invalid-mode',
      message: `Unsupported operating mode "${String(selectedMode)}".`,
      text: null,
    };
  }

  const initialPayload = capturePayload(payload);
  if (!initialPayload) {
    return {
      ok: false,
      status: 'rejected',
      selectedMode,
      inferenceSource: INFERENCE_SOURCES.NONE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason: 'hybridRouter/invalid-payload',
      code: 'hybridRouter/invalid-payload',
      message: 'Payload must be plain, immutable-compatible JSON data.',
      text: null,
    };
  }
  const requestPayload = initialPayload.value;
  const baseCheck = validateBasePayload(requestPayload);
  if (!baseCheck.valid) {
    return {
      ok: false,
      status: 'rejected',
      selectedMode,
      inferenceSource: INFERENCE_SOURCES.NONE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason: baseCheck.code,
      code: baseCheck.code,
      message: baseCheck.reason,
      text: null,
    };
  }

  if (selectedMode === OPERATING_MODES.ESSENTIAL_SECURITY) {
    return runRuleBasedFallback(
      requestPayload,
      selectedMode,
      'essential-security-deterministic-mode',
      startedAt,
      options
    );
  }

  if (selectedMode === OPERATING_MODES.PRIVATE_AI) {
    try {
      const localResult = await generateLocalResponse(requestPayload.prompt, {
        onDownloadProgress: options.onDownloadProgress,
        onDeviceParams: options.onDeviceParams,
        signal: options.signal,
      });

      return {
        ok: true,
        status: 'success',
        selectedMode,
        inferenceSource: localResult.inferenceSource,
        model: 'gemini-nano',
        durationMs: Math.round(getNowMs() - startedAt),
        fallbackReason: null,
        text: localResult.text,
      };
    } catch (error) {
      const reason =
        typeof error?.code === 'string'
          ? error.code
          : 'localAI/unavailable';

      if (getActiveRuleEngine(options.ruleEngine)) {
        return runRuleBasedFallback(
          requestPayload,
          selectedMode,
          reason,
          startedAt,
          options
        );
      }

      return {
        ok: false,
        status: 'unavailable',
        selectedMode,
        inferenceSource: INFERENCE_SOURCES.NONE,
        durationMs: Math.round(getNowMs() - startedAt),
        fallbackReason: reason,
        code: reason,
        message:
          typeof error?.message === 'string'
            ? error.message
            : 'Private on-device AI is unavailable.',
        text: null,
      };
    }
  }

  // CLOUD_ASSISTED_AI: Enforce strict privacy gates BEFORE touching any
  // cloud-capable SDK path (accounting for @firebase/ai chromeAdapter fallback).
  const authResult = await authorizeCloudCapablePayload(
    requestPayload,
    options,
    payload,
    initialPayload.fingerprint
  );
  if (!authResult.authorized) {
    return {
      ok: false,
      status: 'blocked',
      selectedMode,
      inferenceSource: INFERENCE_SOURCES.NONE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason: authResult.code,
      code: authResult.code,
      message: authResult.reason,
      text: null,
    };
  }

  const network = detectNetworkAvailability();
  if (!network.online) {
    const localAvailability = await detectLocalAIAvailability();
    if (localAvailability.canInfer) {
      try {
        const offlineLocal = await generateLocalResponse(
          authResult.sanitizedPrompt,
          {
            onDownloadProgress: options.onDownloadProgress,
            onDeviceParams: options.onDeviceParams,
            signal: options.signal,
          }
        );

        return {
          ok: true,
          status: 'fallback',
          selectedMode,
          inferenceSource: offlineLocal.inferenceSource,
          model: 'gemini-nano',
          durationMs: Math.round(getNowMs() - startedAt),
          fallbackReason: 'offline-local-only',
          text: offlineLocal.text,
        };
      } catch (error) {
        const offlineReason =
          typeof error?.code === 'string' ? error.code : 'hybridRouter/offline';
        return runRuleBasedFallback(
          requestPayload,
          selectedMode,
          offlineReason,
          startedAt,
          options
        );
      }
    }

    return runRuleBasedFallback(
      requestPayload,
      selectedMode,
      'network-offline-local-unavailable',
      startedAt,
      options
    );
  }

  // All privacy gates passed and online: execute Firebase Hybrid SDK PREFER_ON_DEVICE.
  const executor =
    typeof options.hybridExecutor === 'function'
      ? options.hybridExecutor
      : executePreferOnDeviceHybrid;
  const hybridExecutionOptions = getHybridExecutionOptions(
    options,
    authResult.cloudOptions
  );

  try {
    const hybridResult = await executor(
      authResult.sanitizedPrompt,
      hybridExecutionOptions
    );
    const actualSource = hybridResult.inferenceSource;
    const fallbackReason =
      actualSource === InferenceSource.IN_CLOUD
        ? 'on-device-unavailable-cloud-fallback'
        : null;

    return {
      ok: true,
      status: 'success',
      selectedMode,
      inferenceSource: actualSource,
      model: hybridResult.model,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason,
      text: hybridResult.text,
    };
  } catch (error) {
    const failureCode =
      typeof error?.code === 'string'
        ? error.code
        : 'hybridRouter/inference-failed';

    if (getActiveRuleEngine(options.ruleEngine)) {
      return runRuleBasedFallback(
        requestPayload,
        selectedMode,
        failureCode,
        startedAt,
        options
      );
    }

    return {
      ok: false,
      status: 'error',
      selectedMode,
      inferenceSource: INFERENCE_SOURCES.NONE,
      durationMs: Math.round(getNowMs() - startedAt),
      fallbackReason: failureCode,
      code: failureCode,
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'Hybrid cloud-assisted inference failed.',
      text: null,
    };
  }
}
