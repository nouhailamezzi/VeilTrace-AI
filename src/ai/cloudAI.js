import {
  AIError,
  AIErrorCode,
  getAI,
  getGenerativeModel,
  GoogleAIBackend,
  ThinkingLevel,
} from 'firebase/ai';
import { app } from './firebase';
import { initAppCheck } from './appCheck';

/**
 * Currently supported Gemini 3+ general-use model available under the
 * Gemini Developer API free tier (no billing required / Spark-compatible).
 */
export const DEFAULT_CLOUD_MODEL = 'gemini-3.8-flash';

/**
 * Matches the official Firebase AI Logic SDK RequestOptions default (180 seconds).
 */
export const DEFAULT_TIMEOUT_MS = 180_000;

const CLOUD_AI_GLOBAL_KEY = Symbol.for('veiltrace.firebase.cloudAI');

/**
 * Structured error thrown by VeilTrace Cloud AI inference helpers.
 */
export class CloudAIError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {{ causeCode?: string, status?: number, retryable?: boolean }} [meta]
   */
  constructor(code, message, meta = {}) {
    super(message);
    this.name = 'CloudAIError';
    this.code = code;
    this.causeCode = meta.causeCode;
    this.status = meta.status;
    this.retryable = Boolean(meta.retryable);
  }
}

function getNowMs() {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

function matchesAICode(errorCode, expectedCode) {
  return errorCode === expectedCode || errorCode === `ai/${expectedCode}`;
}

/**
 * Normalizes Firebase AI Logic, App Check, quota, model, and network errors
 * while preserving the original Firebase error code (`causeCode`) and HTTP status.
 *
 * @param {unknown} error
 * @param {AbortSignal} [externalSignal]
 * @returns {CloudAIError}
 */
function normalizeCloudAIError(error, externalSignal) {
  if (error instanceof CloudAIError) {
    return error;
  }

  const rawCode = typeof error?.code === 'string' ? error.code : '';
  const rawMessage =
    typeof error?.message === 'string'
      ? error.message
      : 'Cloud AI request failed.';
  const lowerMessage = rawMessage.toLowerCase();
  const status =
    typeof error?.customErrorData?.status === 'number'
      ? error.customErrorData.status
      : typeof error?.status === 'number'
        ? error.status
        : undefined;
  const detailsText = Array.isArray(error?.customErrorData?.errorDetails)
    ? JSON.stringify(error.customErrorData.errorDetails).toLowerCase()
    : '';

  if (
    rawCode.startsWith('appCheck/') ||
    lowerMessage.includes('app check') ||
    lowerMessage.includes('appcheck') ||
    detailsText.includes('app_check')
  ) {
    return new CloudAIError(
      'cloudAI/app-check-error',
      'Firebase App Check verification failed or is not yet ready.',
      { causeCode: rawCode || undefined, status, retryable: false }
    );
  }

  if (matchesAICode(rawCode, AIErrorCode.API_NOT_ENABLED)) {
    return new CloudAIError(
      'cloudAI/api-not-enabled',
      'Firebase AI Logic API is not enabled for this Firebase project.',
      { causeCode: rawCode, status, retryable: false }
    );
  }

  if (
    status === 429 ||
    lowerMessage.includes('quota') ||
    lowerMessage.includes('rate limit') ||
    detailsText.includes('resource_exhausted')
  ) {
    return new CloudAIError(
      'cloudAI/quota-exceeded',
      'Gemini Developer API free-tier quota or rate limit was exceeded.',
      { causeCode: rawCode || undefined, status, retryable: true }
    );
  }

  if (
    status === 404 ||
    matchesAICode(rawCode, AIErrorCode.NO_MODEL) ||
    lowerMessage.includes('not found') ||
    lowerMessage.includes('is not supported for') ||
    lowerMessage.includes('deprecated') ||
    detailsText.includes('not_found')
  ) {
    return new CloudAIError(
      'cloudAI/model-unavailable',
      'The selected Gemini model is unavailable or unsupported for this API.',
      { causeCode: rawCode || undefined, status, retryable: false }
    );
  }

  if (status === 401 || status === 403) {
    return new CloudAIError(
      'cloudAI/app-check-error',
      'Request was rejected (HTTP 401/403). Verify App Check enforcement and Firebase AI Logic provisioning.',
      { causeCode: rawCode || undefined, status, retryable: false }
    );
  }

  if (matchesAICode(rawCode, AIErrorCode.RESPONSE_ERROR)) {
    return new CloudAIError(
      'cloudAI/blocked-response',
      'Gemini Cloud response was blocked or ended abnormally.',
      { causeCode: rawCode, status, retryable: false }
    );
  }

  if (error instanceof AIError) {
    return new CloudAIError('cloudAI/sdk-error', rawMessage, {
      causeCode: rawCode || undefined,
      status,
      retryable: typeof status === 'number' && status >= 500,
    });
  }

  if (externalSignal?.aborted && error?.name === 'AbortError') {
    return new CloudAIError(
      'cloudAI/aborted',
      'Gemini Cloud inference request was aborted by caller signal.',
      { causeCode: rawCode || error.name, status, retryable: false }
    );
  }

  if (error?.name === 'AbortError' || error?.name === 'TimeoutError') {
    return new CloudAIError(
      'cloudAI/timeout',
      'Gemini Cloud inference request timed out.',
      { causeCode: rawCode || error.name, status, retryable: true }
    );
  }

  if (
    error instanceof TypeError ||
    (typeof status === 'number' && status >= 500) ||
    lowerMessage.includes('failed to fetch') ||
    lowerMessage.includes('network') ||
    lowerMessage.includes('error fetching')
  ) {
    return new CloudAIError(
      'cloudAI/network-error',
      'Network error while communicating with Firebase AI Logic.',
      { causeCode: rawCode || undefined, status, retryable: true }
    );
  }

  return new CloudAIError('cloudAI/inference-failed', rawMessage, {
    causeCode: rawCode || undefined,
    status,
    retryable: false,
  });
}

function buildGenerationConfig(customConfig) {
  const userConfig = customConfig ? { ...customConfig } : {};
  const hasThinkingSetting =
    userConfig.thinkingConfig?.thinkingLevel !== undefined ||
    userConfig.thinkingConfig?.thinkingBudget !== undefined;

  if (!hasThinkingSetting) {
    userConfig.thinkingConfig = {
      ...(userConfig.thinkingConfig ?? {}),
      thinkingLevel: ThinkingLevel.LOW,
    };
  }

  return userConfig;
}

/**
 * Ensures Firebase App Check is activated and returns the singleton AI service
 * configured with the Gemini Developer API backend and limited-use App Check tokens.
 *
 * @returns {import('firebase/ai').AI}
 */
export function getCloudAI() {
  const appCheckInstance = initAppCheck();
  if (!appCheckInstance) {
    throw new CloudAIError(
      'cloudAI/app-check-not-initialized',
      'Firebase App Check must be initialized in a browser environment before calling Cloud AI.'
    );
  }

  const existing = globalThis[CLOUD_AI_GLOBAL_KEY];
  if (existing && existing.app === app) {
    return existing;
  }

  const ai = getAI(app, {
    backend: new GoogleAIBackend(),
    useLimitedUseAppCheckTokens: true,
  });

  globalThis[CLOUD_AI_GLOBAL_KEY] = ai;
  return ai;
}

/**
 * Executes genuine Gemini Cloud inference through Firebase AI Logic.
 *
 * @param {string} prompt
 * @param {{
 *   model?: string,
 *   systemInstruction?: string,
 *   generationConfig?: import('firebase/ai').GenerationConfig,
 *   timeoutMs?: number,
 *   signal?: AbortSignal
 * }} [options]
 * @returns {Promise<{
 *   ok: true,
 *   status: 'success',
 *   model: string,
 *   text: string,
 *   durationMs: number
 * }>}
 */
export async function generateCloudResponse(prompt, options = {}) {
  if (typeof prompt !== 'string' || prompt.trim().length === 0) {
    throw new CloudAIError(
      'cloudAI/invalid-input',
      'Prompt must be a non-empty string.'
    );
  }

  const selectedModel =
    typeof options.model === 'string' && options.model.trim().length > 0
      ? options.model.trim()
      : DEFAULT_CLOUD_MODEL;

  const timeoutMs =
    typeof options.timeoutMs === 'number' && options.timeoutMs > 0
      ? options.timeoutMs
      : DEFAULT_TIMEOUT_MS;

  const generationConfig = buildGenerationConfig(options.generationConfig);
  const startedAt = getNowMs();

  console.info('[CloudAI] Request initialized:', {
    model: selectedModel,
    timeoutMs,
    thinkingLevel: generationConfig.thinkingConfig?.thinkingLevel ?? 'custom',
  });

  try {
    const ai = getCloudAI();

    const modelParams = {
      model: selectedModel,
      generationConfig,
      ...(options.systemInstruction
        ? { systemInstruction: options.systemInstruction }
        : {}),
    };

    const requestOptions = { timeout: timeoutMs };
    const generativeModel = getGenerativeModel(ai, modelParams, requestOptions);

    const singleRequestOptions = {
      timeout: timeoutMs,
      ...(options.signal ? { signal: options.signal } : {}),
    };
    const result = await generativeModel.generateContent(
      prompt,
      singleRequestOptions
    );

    const text = result?.response?.text?.()?.trim() ?? '';
    const durationMs = Math.round(getNowMs() - startedAt);

    if (!text) {
      throw new CloudAIError(
        'cloudAI/empty-response',
        'Gemini Cloud returned an empty response.'
      );
    }

    console.info('[CloudAI] Request completed:', {
      model: selectedModel,
      durationMs,
      status: 'success',
    });

    return {
      ok: true,
      status: 'success',
      model: selectedModel,
      text,
      durationMs,
    };
  } catch (error) {
    const durationMs = Math.round(getNowMs() - startedAt);
    const normalizedError = normalizeCloudAIError(error, options.signal);

    console.error('[CloudAI] Request failed:', {
      model: selectedModel,
      durationMs,
      code: normalizedError.code,
      originalCode: normalizedError.causeCode ?? null,
      httpStatus: normalizedError.status ?? null,
    });

    throw normalizedError;
  }
}
