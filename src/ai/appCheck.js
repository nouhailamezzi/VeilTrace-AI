import {
  initializeAppCheck,
  ReCaptchaEnterpriseProvider,
} from 'firebase/app-check';
import { app } from './firebase';

const APP_CHECK_GLOBAL_KEY = Symbol.for('veiltrace.firebase.appCheck');

/**
 * Enables App Check debug mode strictly during Vite development builds.
 * Vite replaces `import.meta.env.DEV` with `false` and `import.meta.env.PROD`
 * with `true` in production builds, allowing dead-code elimination to strip
 * this block from production bundles.
 */
function configureDevelopmentDebugMode() {
  if (
    import.meta.env.DEV &&
    !import.meta.env.PROD &&
    typeof self !== 'undefined'
  ) {
    const configuredDebugToken =
      import.meta.env.VITE_APPCHECK_DEBUG_TOKEN?.trim();
    self.FIREBASE_APPCHECK_DEBUG_TOKEN = configuredDebugToken || true;
  }
}

/**
 * Initializes Firebase App Check once for the Firebase app using
 * Fraud Defense (reCAPTCHA Enterprise) with automatic token refresh.
 * Idempotent across repeated calls and Vite HMR reloads.
 *
 * @returns {import('firebase/app-check').AppCheck | null}
 */
export function initAppCheck() {
  const existingInstance = globalThis[APP_CHECK_GLOBAL_KEY];
  if (existingInstance && existingInstance.app === app) {
    return existingInstance;
  }

  if (typeof window === 'undefined') {
    return null;
  }

  const siteKey = import.meta.env.VITE_RECAPTCHA_ENTERPRISE_SITE_KEY?.trim();
  if (!siteKey) {
    throw new Error(
      'Missing VITE_RECAPTCHA_ENTERPRISE_SITE_KEY environment variable for Firebase App Check.'
    );
  }

  configureDevelopmentDebugMode();

  const instance = initializeAppCheck(app, {
    provider: new ReCaptchaEnterpriseProvider(siteKey),
    isTokenAutoRefreshEnabled: true,
  });

  globalThis[APP_CHECK_GLOBAL_KEY] = instance;
  return instance;
}

export const appCheck = initAppCheck();
export default appCheck;
