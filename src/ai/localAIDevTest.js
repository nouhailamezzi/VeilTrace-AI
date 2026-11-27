import {
  detectLocalAIAvailability,
  generateLocalResponse,
} from './localAI';

/**
 * Short synthetic cybersecurity prompt used strictly for development verification.
 * Never transmits real logs, IP addresses, credentials, or confidential data.
 */
const SYNTHETIC_LOCAL_SECURITY_PROMPT =
  'Synthetic training triage (not real): A user received an unexpected password-reset email from a lookalike domain. List 3 brief bullet points for verification, containment, and user guidance.';

function getNowMs() {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

/**
 * Development-only inspection of on-device Gemini Nano availability.
 *
 * @returns {Promise<Awaited<ReturnType<typeof detectLocalAIAvailability>>>}
 */
export async function runLocalAIStatusTest() {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      status: 'disabled',
      rawAvailability: null,
      supported: false,
      canInfer: false,
      requiresDownload: false,
      reason: 'Development-only test is disabled in production builds.',
      advisoryHints: null,
    };
  }

  const availability = await detectLocalAIAvailability();
  console.info('[LocalAI Status]', availability);
  return availability;
}

/**
 * Development-only test for genuine on-device Gemini Nano inference via the
 * Firebase AI Logic Hybrid SDK (`ONLY_ON_DEVICE`). Never simulates output.
 *
 * @param {{
 *   initializeIfDownloadable?: boolean,
 *   onDownloadProgress?: (progress: number) => void,
 *   signal?: AbortSignal
 * }} [options]
 * @returns {Promise<{
 *   ok: boolean,
 *   availability: Awaited<ReturnType<typeof detectLocalAIAvailability>> | null,
 *   status: string,
 *   durationMs: number,
 *   inferenceSource?: string,
 *   response: string | null,
 *   code?: string,
 *   originalCode?: string,
 *   message?: string
 * }>}
 */
export async function runLocalAIDevTest(options = {}) {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      ok: false,
      availability: null,
      status: 'disabled',
      durationMs: 0,
      response: null,
      code: 'localAI/dev-test-disabled-in-production',
    };
  }

  const startedAt = getNowMs();
  const availability = await detectLocalAIAvailability();

  try {
    const inference = await generateLocalResponse(
      SYNTHETIC_LOCAL_SECURITY_PROMPT,
      {
        initializeIfDownloadable: options.initializeIfDownloadable ?? true,
        onDownloadProgress:
          options.onDownloadProgress ??
          ((progress) => {
            console.info(
              `[LocalAI Test] Model download progress: ${Math.round(progress * 100)}%`
            );
          }),
        signal: options.signal,
      }
    );

    const output = {
      ok: true,
      availability: inference.availability,
      status: inference.status,
      inferenceSource: inference.inferenceSource,
      durationMs: inference.durationMs,
      response: inference.text,
    };

    console.info('[LocalAI Test] Success:', {
      status: output.status,
      inferenceSource: output.inferenceSource,
      durationMs: output.durationMs,
    });

    return output;
  } catch (error) {
    const output = {
      ok: false,
      availability,
      status: 'error',
      durationMs: Math.round(getNowMs() - startedAt),
      response: null,
      code:
        typeof error?.code === 'string' && error.code.length > 0
          ? error.code
          : 'localAI/unknown-error',
      ...(error?.causeCode ? { originalCode: error.causeCode } : {}),
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'On-device Gemini Nano test failed.',
    };

    console.error('[LocalAI Test] Failed:', {
      status: output.status,
      code: output.code,
      originalCode: output.originalCode ?? null,
      availabilityStatus: availability.status,
      durationMs: output.durationMs,
    });

    return output;
  }
}

if (
  import.meta.env.DEV &&
  !import.meta.env.PROD &&
  typeof window !== 'undefined'
) {
  window.__veiltraceLocalAIStatus = runLocalAIStatusTest;
  window.__veiltraceLocalAITest = runLocalAIDevTest;
}
