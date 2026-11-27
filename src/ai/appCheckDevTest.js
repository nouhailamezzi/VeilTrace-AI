import { getToken } from 'firebase/app-check';
import { initAppCheck } from './appCheck';

/**
 * Development-only runtime verification for Firebase App Check.
 * Uses `getToken` from the same `firebase/app-check` module instance used by
 * the application and reports success or an error code without exposing tokens.
 *
 * @param {{ forceRefresh?: boolean }} [options]
 * @returns {Promise<{ ok: boolean, code: string }>}
 */
export async function runAppCheckRuntimeTest({ forceRefresh = false } = {}) {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      ok: false,
      code: 'appCheck/dev-test-disabled-in-production',
    };
  }

  try {
    const appCheckInstance = initAppCheck();
    if (!appCheckInstance) {
      const result = { ok: false, code: 'appCheck/not-initialized' };
      console.error('[AppCheck Test]', result);
      return result;
    }

    const tokenResult = await getToken(appCheckInstance, forceRefresh);
    const hasToken =
      typeof tokenResult?.token === 'string' && tokenResult.token.length > 0;

    if (!hasToken) {
      const result = { ok: false, code: 'appCheck/empty-token' };
      console.error('[AppCheck Test]', result);
      return result;
    }

    const result = { ok: true, code: 'ok' };
    console.info('[AppCheck Test]', result);
    return result;
  } catch (error) {
    const code =
      typeof error?.code === 'string' && error.code.length > 0
        ? error.code
        : 'appCheck/unknown-error';
    const result = { ok: false, code };
    console.error('[AppCheck Test]', result);
    return result;
  }
}

if (
  import.meta.env.DEV &&
  !import.meta.env.PROD &&
  typeof window !== 'undefined'
) {
  window.__veiltraceAppCheckTest = runAppCheckRuntimeTest;
}
