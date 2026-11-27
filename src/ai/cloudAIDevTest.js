import { ThinkingLevel } from 'firebase/ai';
import { DEFAULT_CLOUD_MODEL, generateCloudResponse } from './cloudAI';

/**
 * Short, fixed synthetic cybersecurity prompt used strictly for development
 * verification. Contains no real logs, IP addresses, credentials, or secrets.
 */
const SYNTHETIC_CYBERSECURITY_PROMPT =
  'Synthetic training triage (not real): A user received an unexpected password-reset email from a lookalike domain. List 3 brief bullet points for verification, containment, and user guidance.';

function getNowMs() {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

/**
 * Development-only browser runtime test for genuine Gemini Cloud inference.
 *
 * @returns {Promise<{
 *   ok: boolean,
 *   status: string,
 *   model: string,
 *   durationMs: number,
 *   response: string | null,
 *   code?: string,
 *   originalCode?: string,
 *   httpStatus?: number,
 *   message?: string
 * }>}
 */
export async function runCloudAIDevTest() {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      ok: false,
      status: 'disabled',
      model: DEFAULT_CLOUD_MODEL,
      durationMs: 0,
      response: null,
      code: 'cloudAI/dev-test-disabled-in-production',
    };
  }

  const startedAt = getNowMs();

  try {
    const inference = await generateCloudResponse(
      SYNTHETIC_CYBERSECURITY_PROMPT,
      {
        generationConfig: {
          maxOutputTokens: 200,
          thinkingConfig: {
            thinkingLevel: ThinkingLevel.LOW,
          },
        },
      }
    );

    const output = {
      ok: true,
      status: inference.status,
      model: inference.model,
      durationMs: inference.durationMs,
      response: inference.text,
    };

    console.info('[CloudAI Test] Success:', {
      status: output.status,
      model: output.model,
      durationMs: output.durationMs,
    });

    return output;
  } catch (error) {
    const output = {
      ok: false,
      status: 'error',
      model: DEFAULT_CLOUD_MODEL,
      durationMs: Math.round(getNowMs() - startedAt),
      response: null,
      code:
        typeof error?.code === 'string' && error.code.length > 0
          ? error.code
          : 'cloudAI/unknown-error',
      ...(error?.causeCode ? { originalCode: error.causeCode } : {}),
      ...(typeof error?.status === 'number'
        ? { httpStatus: error.status }
        : {}),
      message:
        typeof error?.message === 'string'
          ? error.message
          : 'Cloud AI inference test failed.',
    };

    console.error('[CloudAI Test] Failed:', {
      status: output.status,
      code: output.code,
      originalCode: output.originalCode ?? null,
      httpStatus: output.httpStatus ?? null,
      model: output.model,
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
  window.__veiltraceCloudAITest = runCloudAIDevTest;
}
