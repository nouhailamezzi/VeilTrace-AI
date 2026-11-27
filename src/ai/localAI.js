import {
  AIError,
  AIErrorCode,
  getAI,
  getGenerativeModel,
  GoogleAIBackend,
  InferenceMode,
  InferenceSource,
} from 'firebase/ai';
import { app } from './firebase';
import { initAppCheck } from './appCheck';

/**
 * Default on-device session expectations aligned with @firebase/ai ChromeAdapter.
 */
export const DEFAULT_ON_DEVICE_CREATE_OPTIONS = Object.freeze({
  expectedInputs: [{ type: 'text', languages: ['en'] }],
  expectedOutputs: [{ type: 'text', languages: ['en'] }],
});

const LOCAL_AI_GLOBAL_KEY = Symbol.for('veiltrace.firebase.localAI');

/**
 * Structured error thrown by VeilTrace on-device Gemini Nano inference helpers.
 */
export class LocalAIError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ causeCode?: string, availability?: string }} [meta]
   */
  constructor(code, message, meta = {}) {
    super(message);
    this.name = 'LocalAIError';
    this.code = code;
    this.causeCode = meta.causeCode;
    this.availability = meta.availability;
  }
}

function getNowMs() {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function getLanguageModelProvider() {
  if (typeof globalThis === 'undefined') {
    return null;
  }
  const provider = globalThis.LanguageModel;
  if (
    provider &&
    typeof provider.availability === 'function' &&
    typeof provider.create === 'function'
  ) {
    return provider;
  }
  return null;
}

function collectAdvisoryClientHints() {
  if (typeof navigator === 'undefined') {
    return null;
  }

  return {
    hardwareConcurrency:
      typeof navigator.hardwareConcurrency === 'number'
        ? navigator.hardwareConcurrency
        : null,
    deviceMemoryGB:
      typeof navigator.deviceMemory === 'number'
        ? navigator.deviceMemory
        : null,
    isMobilePlatform:
      typeof navigator.userAgentData?.mobile === 'boolean'
        ? navigator.userAgentData.mobile
        : null,
  };
}

function matchesAICode(errorCode, expectedCode) {
  return errorCode === expectedCode || errorCode === `ai/${expectedCode}`;
}

/**
 * Normalizes Chrome Prompt API and Firebase Hybrid SDK errors into predictable
 * LocalAIError codes without ever falling back to cloud inference.
 *
 * @param {unknown} error
 * @param {AbortSignal} [signal]
 * @param {string | null} [availability]
 * @returns {LocalAIError}
 */
function normalizeLocalAIError(error, signal, availability = null) {
  if (error instanceof LocalAIError) {
    return error;
  }

  const rawCode = typeof error?.code === 'string' ? error.code : '';
  const rawName = typeof error?.name === 'string' ? error.name : '';
  const rawMessage =
    typeof error?.message === 'string'
      ? error.message
      : 'On-device Gemini Nano operation failed.';
  const lowerMessage = rawMessage.toLowerCase();

  if (signal?.aborted || rawName === 'AbortError') {
    return new LocalAIError(
      'localAI/aborted',
      'On-device inference or model initialization was aborted.',
      { causeCode: rawCode || rawName || 'AbortError', availability: availability ?? undefined }
    );
  }

  if (rawName === 'NotAllowedError' || lowerMessage.includes('user gesture')) {
    return new LocalAIError(
      'localAI/user-gesture-required',
      'Downloading or initializing Gemini Nano requires a direct user interaction (such as a button click).',
      { causeCode: rawCode || rawName, availability: availability ?? undefined }
    );
  }

  if (
    matchesAICode(rawCode, AIErrorCode.UNSUPPORTED) ||
    lowerMessage.includes('unsupported browser')
  ) {
    return new LocalAIError(
      'localAI/unsupported-browser',
      'Chrome Built-in AI (LanguageModel API) is not supported in this browser.',
      { causeCode: rawCode || undefined, availability: availability ?? undefined }
    );
  }

  if (
    matchesAICode(rawCode, AIErrorCode.API_NOT_ENABLED) ||
    lowerMessage.includes('not available in this environment')
  ) {
    return new LocalAIError(
      'localAI/unavailable',
      'On-device Gemini Nano is unavailable on this device or browser configuration.',
      { causeCode: rawCode || undefined, availability: availability ?? undefined }
    );
  }

  if (error instanceof AIError) {
    return new LocalAIError('localAI/sdk-error', rawMessage, {
      causeCode: rawCode || undefined,
      availability: availability ?? undefined,
    });
  }

  return new LocalAIError('localAI/inference-failed', rawMessage, {
    causeCode: rawCode || rawName || undefined,
    availability: availability ?? undefined,
  });
}

/**
 * Ensures App Check is initialized and returns the Firebase AI service instance
 * matching the project's App Check configuration (`useLimitedUseAppCheckTokens: true`).
 *
 * @returns {import('firebase/ai').AI}
 */
function getHybridAIInstance() {
  const appCheckInstance = initAppCheck();
  if (!appCheckInstance) {
    throw new LocalAIError(
      'localAI/app-check-not-initialized',
      'Firebase App Check must be initialized in a browser environment.'
    );
  }

  const existing = globalThis[LOCAL_AI_GLOBAL_KEY];
  if (existing && existing.app === app) {
    return existing;
  }

  const ai = getAI(app, {
    backend: new GoogleAIBackend(),
    useLimitedUseAppCheckTokens: true,
  });

  globalThis[LOCAL_AI_GLOBAL_KEY] = ai;
  return ai;
}

/**
 * Detects genuine on-device Gemini Nano capability using Chrome's Prompt API
 * (`LanguageModel.availability`) without simulating availability.
 *
 * Note: Chrome's `LanguageModel.availability()` returns a single `'unavailable'`
 * state for hardware insufficiency, unsupported OS/mobile, or disabled flags
 * without exposing a distinct hardware-vs-policy reason code.
 *
 * @param {import('firebase/ai').LanguageModelCreateCoreOptions} [createOptions]
 * @returns {Promise<{
 *   status: 'unsupported-environment' | 'unsupported-browser' | 'unavailable' | 'downloadable' | 'downloading' | 'ready' | 'error',
 *   rawAvailability: 'unavailable' | 'downloadable' | 'downloading' | 'available' | null,
 *   supported: boolean,
 *   canInfer: boolean,
 *   requiresDownload: boolean,
 *   reason: string,
 *   advisoryHints: { hardwareConcurrency: number | null, deviceMemoryGB: number | null, isMobilePlatform: boolean | null } | null
 * }>}
 */
export async function detectLocalAIAvailability(
  createOptions = DEFAULT_ON_DEVICE_CREATE_OPTIONS
) {
  if (typeof window === 'undefined') {
    return {
      status: 'unsupported-environment',
      rawAvailability: null,
      supported: false,
      canInfer: false,
      requiresDownload: false,
      reason: 'On-device Gemini Nano requires a browser window environment.',
      advisoryHints: null,
    };
  }

  const advisoryHints = collectAdvisoryClientHints();
  const provider = getLanguageModelProvider();

  if (!provider) {
    return {
      status: 'unsupported-browser',
      rawAvailability: null,
      supported: false,
      canInfer: false,
      requiresDownload: false,
      reason:
        'Chrome Built-in AI LanguageModel API is not present in this browser.',
      advisoryHints,
    };
  }

  try {
    const rawAvailability = await provider.availability(createOptions);

    switch (rawAvailability) {
      case 'available':
        return {
          status: 'ready',
          rawAvailability,
          supported: true,
          canInfer: true,
          requiresDownload: false,
          reason: 'Gemini Nano is downloaded and ready for on-device inference.',
          advisoryHints,
        };
      case 'downloadable':
        return {
          status: 'downloadable',
          rawAvailability,
          supported: true,
          canInfer: false,
          requiresDownload: true,
          reason:
            'Gemini Nano is supported and downloadable; a user-initiated download is required before inference.',
          advisoryHints,
        };
      case 'downloading':
        return {
          status: 'downloading',
          rawAvailability,
          supported: true,
          canInfer: false,
          requiresDownload: true,
          reason: 'Gemini Nano is currently downloading in Chrome.',
          advisoryHints,
        };
      case 'unavailable':
      default:
        return {
          status: 'unavailable',
          rawAvailability: rawAvailability ?? 'unavailable',
          supported: false,
          canInfer: false,
          requiresDownload: false,
          reason:
            'Gemini Nano returned "unavailable" (unsupported hardware, unsupported OS/mobile device, insufficient storage/RAM/VRAM, or Chrome Built-in AI not enabled).',
          advisoryHints,
        };
    }
  } catch (error) {
    return {
      status: 'error',
      rawAvailability: null,
      supported: false,
      canInfer: false,
      requiresDownload: false,
      reason:
        typeof error?.message === 'string'
          ? error.message
          : 'Failed to query Chrome LanguageModel availability.',
      advisoryHints,
    };
  }
}

/**
 * Creates a Firebase Hybrid SDK `GenerativeModel` strictly configured for
 * `InferenceMode.ONLY_ON_DEVICE` (never falling back to cloud).
 *
 * @param {import('firebase/ai').OnDeviceParams} [onDeviceParams]
 * @returns {import('firebase/ai').GenerativeModel}
 */
function createLocalGenerativeModel(onDeviceParams = {}) {
  const ai = getHybridAIInstance();
  const createOptions = {
    ...DEFAULT_ON_DEVICE_CREATE_OPTIONS,
    ...(onDeviceParams.createOptions ?? {}),
  };
  const configuredOnDeviceParams = {
    ...onDeviceParams,
    createOptions,
  };
  const pinnedAI = createOnDeviceOnlyAI(ai, configuredOnDeviceParams);

  return getGenerativeModel(pinnedAI, {
    mode: InferenceMode.ONLY_ON_DEVICE,
    onDeviceParams: configuredOnDeviceParams,
  });
}

/**
 * Pins Firebase AI Logic to a verified Chrome adapter. The installed SDK
 * falls back to cloud when its adapter factory returns no adapter, even in
 * ONLY_ON_DEVICE mode, so the model factory must not be allowed to recreate it.
 *
 * @param {import('firebase/ai').AI} ai
 * @param {import('firebase/ai').OnDeviceParams} [onDeviceParams]
 * @param {Window} [targetWindow]
 * @returns {import('firebase/ai').AI}
 */
export function createOnDeviceOnlyAI(
  ai,
  onDeviceParams = {},
  targetWindow = typeof window === 'undefined' ? undefined : window
) {
  if (
    !targetWindow ||
    typeof ai?.chromeAdapterFactory !== 'function'
  ) {
    throw new LocalAIError(
      'localAI/local-only-unavailable',
      'Firebase AI Logic cannot guarantee on-device-only execution in this environment.'
    );
  }

  const adapter = ai.chromeAdapterFactory(
    InferenceMode.ONLY_ON_DEVICE,
    targetWindow,
    onDeviceParams
  );
  if (
    !adapter ||
    adapter.mode !== InferenceMode.ONLY_ON_DEVICE ||
    typeof adapter.isAvailable !== 'function' ||
    typeof adapter.generateContent !== 'function' ||
    typeof adapter.downloadIfAvailable !== 'function'
  ) {
    throw new LocalAIError(
      'localAI/local-only-unavailable',
      'Firebase AI Logic did not provide a verified ONLY_ON_DEVICE adapter; inference was blocked.'
    );
  }

  const pinnedAI = Object.assign(
    Object.create(Object.getPrototypeOf(ai)),
    ai,
    { chromeAdapterFactory: () => adapter }
  );
  return pinnedAI;
}

function raceWithAbortSignal(promise, signal) {
  if (!signal) {
    return promise;
  }

  if (signal.aborted) {
    return Promise.reject(
      new LocalAIError(
        'localAI/aborted',
        'On-device operation was aborted before starting.'
      )
    );
  }

  return new Promise((resolve, reject) => {
    const onAbort = () => {
      reject(
        new LocalAIError(
          'localAI/aborted',
          'On-device operation was aborted by caller signal.'
        )
      );
    };

    signal.addEventListener('abort', onAbort, { once: true });

    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      }
    );
  });
}

/**
 * Explicitly initializes (and downloads if downloadable) the on-device
 * Gemini Nano model through the Firebase AI Logic Hybrid SDK.
 * Must be called after a user gesture when `status === 'downloadable'`.
 *
 * @param {{
 *   onDownloadProgress?: (progress: number) => void,
 *   onDeviceParams?: import('firebase/ai').OnDeviceParams,
 *   signal?: AbortSignal
 * }} [options]
 * @returns {Promise<{
 *   ok: true,
 *   status: 'ready',
 *   availability: Awaited<ReturnType<typeof detectLocalAIAvailability>>
 * }>}
 */
export async function initializeLocalModel(options = {}) {
  const createOptions = {
    ...DEFAULT_ON_DEVICE_CREATE_OPTIONS,
    ...(options.onDeviceParams?.createOptions ?? {}),
    ...(options.signal ? { signal: options.signal } : {}),
  };

  const availability = await detectLocalAIAvailability(createOptions);

  if (availability.status === 'unsupported-environment' || availability.status === 'unsupported-browser') {
    throw new LocalAIError('localAI/unsupported-browser', availability.reason, {
      availability: availability.status,
    });
  }

  if (availability.status === 'unavailable' || availability.status === 'error') {
    throw new LocalAIError('localAI/unavailable', availability.reason, {
      availability: availability.status,
    });
  }

  if (availability.status === 'ready') {
    return {
      ok: true,
      status: 'ready',
      availability,
    };
  }

  try {
    const model = createLocalGenerativeModel({
      ...(options.onDeviceParams ?? {}),
      createOptions,
    });

    await raceWithAbortSignal(
      model.initializeDeviceModel(options.onDownloadProgress),
      options.signal
    );

    const updatedAvailability = await detectLocalAIAvailability(createOptions);
    if (updatedAvailability.status !== 'ready') {
      throw new LocalAIError(
        'localAI/not-ready',
        `On-device model initialization finished in unexpected state "${updatedAvailability.status}".`,
        { availability: updatedAvailability.status }
      );
    }

    return {
      ok: true,
      status: 'ready',
      availability: updatedAvailability,
    };
  } catch (error) {
    throw normalizeLocalAIError(error, options.signal, availability.status);
  }
}

/**
 * Executes genuine on-device Gemini Nano inference via the Firebase AI Logic
 * Hybrid SDK (`InferenceMode.ONLY_ON_DEVICE`).
 *
 * Security guarantee: Fails closed before invoking `generateContent` whenever
 * `LanguageModel` is absent or unavailable, preventing `@firebase/ai` from
 * ever falling back to cloud inference if `chromeAdapter` is undefined.
 *
 * @param {string} prompt
 * @param {{
 *   onDownloadProgress?: (progress: number) => void,
 *   initializeIfDownloadable?: boolean,
 *   onDeviceParams?: import('firebase/ai').OnDeviceParams,
 *   signal?: AbortSignal
 * }} [options]
 * @returns {Promise<{
 *   ok: true,
 *   status: 'success',
 *   inferenceSource: string,
 *   availability: Awaited<ReturnType<typeof detectLocalAIAvailability>>,
 *   text: string,
 *   durationMs: number
 * }>}
 */
export async function generateLocalResponse(prompt, options = {}) {
  if (typeof prompt !== 'string' || prompt.trim().length === 0) {
    throw new LocalAIError(
      'localAI/invalid-input',
      'Prompt must be a non-empty string.'
    );
  }

  if (options.signal?.aborted) {
    throw new LocalAIError(
      'localAI/aborted',
      'On-device inference was aborted before starting.'
    );
  }

  const createOptions = {
    ...DEFAULT_ON_DEVICE_CREATE_OPTIONS,
    ...(options.onDeviceParams?.createOptions ?? {}),
    ...(options.signal ? { signal: options.signal } : {}),
  };

  const promptOptions = {
    ...(options.onDeviceParams?.promptOptions ?? {}),
    ...(options.signal ? { signal: options.signal } : {}),
  };

  const availability = await detectLocalAIAvailability(createOptions);

  // Fail closed strictly before calling generateContent so @firebase/ai never
  // routes to inCloudCall() when Chrome's LanguageModel API is absent.
  if (
    availability.status === 'unsupported-environment' ||
    availability.status === 'unsupported-browser'
  ) {
    throw new LocalAIError('localAI/unsupported-browser', availability.reason, {
      availability: availability.status,
    });
  }

  if (availability.status === 'unavailable' || availability.status === 'error') {
    throw new LocalAIError('localAI/unavailable', availability.reason, {
      availability: availability.status,
    });
  }

  if (
    (availability.status === 'downloadable' ||
      availability.status === 'downloading') &&
    options.initializeIfDownloadable === false
  ) {
    throw new LocalAIError(
      'localAI/model-not-downloaded',
      availability.reason,
      { availability: availability.status }
    );
  }

  const startedAt = getNowMs();

  console.info('[LocalAI] Request initialized:', {
    mode: InferenceMode.ONLY_ON_DEVICE,
    availability: availability.status,
  });

  try {
    const model = createLocalGenerativeModel({
      ...(options.onDeviceParams ?? {}),
      createOptions,
      promptOptions,
    });

    if (
      availability.status === 'downloadable' ||
      availability.status === 'downloading'
    ) {
      await raceWithAbortSignal(
        model.initializeDeviceModel(options.onDownloadProgress),
        options.signal
      );
    }

    const result = await raceWithAbortSignal(
      model.generateContent(
        prompt,
        options.signal ? { signal: options.signal } : undefined
      ),
      options.signal
    );

    if (result?.response?.inferenceSource !== InferenceSource.ON_DEVICE) {
      throw new LocalAIError(
        'localAI/cloud-fallback-blocked',
        'Blocked non-on-device inference response in ONLY_ON_DEVICE mode.',
        { availability: availability.status }
      );
    }

    const text = result?.response?.text?.()?.trim() ?? '';
    const durationMs = Math.round(getNowMs() - startedAt);

    if (!text) {
      throw new LocalAIError(
        'localAI/empty-response',
        'On-device Gemini Nano returned an empty response.',
        { availability: availability.status }
      );
    }

    console.info('[LocalAI] Request completed:', {
      status: 'success',
      inferenceSource: result.response.inferenceSource,
      durationMs,
    });

    return {
      ok: true,
      status: 'success',
      inferenceSource: result.response.inferenceSource,
      availability,
      text,
      durationMs,
    };
  } catch (error) {
    const durationMs = Math.round(getNowMs() - startedAt);
    const normalizedError = normalizeLocalAIError(
      error,
      options.signal,
      availability.status
    );

    console.error('[LocalAI] Request failed:', {
      code: normalizedError.code,
      originalCode: normalizedError.causeCode ?? null,
      availability: normalizedError.availability ?? availability.status,
      durationMs,
    });

    throw normalizedError;
  }
}
