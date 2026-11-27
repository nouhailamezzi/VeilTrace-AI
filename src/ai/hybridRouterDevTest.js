import { InferenceMode } from 'firebase/ai';
import {
  createOnDeviceOnlyAI,
} from './localAI';
import {
  detectHybridCapabilities,
  OPERATING_MODES,
  registerConsentHandler,
  registerPrivacyFirewall,
  registerRuleEngine,
  routeInference,
} from './hybridRouter';

const SYNTHETIC_SANITIZED_PROMPT =
  'Synthetic training triage (not real): A user received an unexpected password-reset email from a lookalike domain. List 3 brief bullet points for verification, containment, and user guidance.';

const DEV_SYNTHETIC_ONLY_FIREWALL = {
  validateCloudPayload(payload) {
    return payload?.sanitized === true &&
      payload?.prompt === SYNTHETIC_SANITIZED_PROMPT
      ? {
          allowed: true,
          sanitizedPrompt: SYNTHETIC_SANITIZED_PROMPT,
        }
      : {
          allowed: false,
          code: 'devFirewall/non-synthetic-rejected',
          reason: 'Dev test firewall only allows the fixed synthetic prompt.',
        };
  },
};

function assertTest(condition, name) {
  if (!condition) {
    throw new Error(`Hybrid router security test failed: ${name}`);
  }
  return { name, passed: true };
}

/**
 * Development-only capability check for the hybrid router.
 */
export async function runHybridRouterStatusTest() {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      status: 'disabled',
      reason: 'Development-only test is disabled in production builds.',
    };
  }

  const capabilities = await detectHybridCapabilities();
  console.info('[HybridRouter Status]', capabilities);
  return capabilities;
}

/**
 * Deterministic, network-free security tests by default.
 * A live cloud request runs only when `runLiveCloudTest === true`.
 *
 * @param {{ runLiveCloudTest?: boolean }} [options]
 */
export async function runHybridRouterDevTest(options = {}) {
  if (!import.meta.env.DEV || import.meta.env.PROD) {
    return {
      ok: false,
      status: 'disabled',
      code: 'hybridRouter/dev-test-disabled-in-production',
    };
  }

  let restoreFirewall = () => {};
  let restoreRuleEngine = () => {};
  let restoreConsent = () => {};
  let consentCalls = 0;

  const onlineDescriptor =
    typeof navigator === 'undefined'
      ? undefined
      : Object.getOwnPropertyDescriptor(navigator, 'onLine');
  let networkMockInstalled = false;

  try {
    restoreFirewall = registerPrivacyFirewall(DEV_SYNTHETIC_ONLY_FIREWALL);
    restoreRuleEngine = registerRuleEngine({
      analyze: async () => ({ summary: 'Synthetic deterministic rule result.' }),
    });
    restoreConsent = registerConsentHandler((payload, context) => {
      consentCalls += 1;
      return (
        Object.isFrozen(payload) &&
        payload.prompt === SYNTHETIC_SANITIZED_PROMPT &&
        context.sanitizedPrompt === SYNTHETIC_SANITIZED_PROMPT
      );
    });

    if (typeof navigator !== 'undefined') {
      Object.defineProperty(navigator, 'onLine', {
        configurable: true,
        value: true,
      });
      networkMockInstalled = true;
    }

    let blockedCloudInvocationCount = 0;
    let mockedCloudInvocationCount = 0;
    const blockedCloudExecutor = async () => {
      blockedCloudInvocationCount += 1;
      throw new Error('Blocked test unexpectedly reached its cloud executor.');
    };
    const mockedCloudExecutor = async (prompt) => {
      mockedCloudInvocationCount += 1;
      return {
        text: `Mock response for: ${prompt}`,
        model: 'mock-model',
        inferenceSource: 'in_cloud',
      };
    };

    const missingFirewallRestore = registerPrivacyFirewall(null);
    let missingFirewallResult;
    try {
      missingFirewallResult = await routeInference(
        { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          hybridExecutor: blockedCloudExecutor,
        }
      );
    } finally {
      missingFirewallRestore();
    }

    const missingConsentRestore = registerConsentHandler(null);
    let booleanConsentResult;
    try {
      booleanConsentResult = await routeInference(
        {
          prompt: SYNTHETIC_SANITIZED_PROMPT,
          sanitized: true,
          userConsent: true,
        },
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          userConsent: true,
          hybridExecutor: blockedCloudExecutor,
        }
      );
    } finally {
      missingConsentRestore();
    }

    const rawPayloadResult = await routeInference(
      {
        prompt: 'Synthetic placeholder',
        classification: 'raw',
        containsRawConfidentialData: true,
        sanitized: true,
      },
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        hybridExecutor: blockedCloudExecutor,
      }
    );

    const credentialPayloadResult = await routeInference(
      {
        prompt: 'Synthetic access review',
        sanitized: true,
        credentials: { password: 'synthetic-not-a-secret' },
      },
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        hybridExecutor: blockedCloudExecutor,
      }
    );

    const rawLogsResult = await routeInference(
      {
        prompt: SYNTHETIC_SANITIZED_PROMPT,
        sanitized: true,
        rawLogs: [],
      },
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        hybridExecutor: blockedCloudExecutor,
      }
    );

    let accessorReadCount = 0;
    const accessorPayload = { sanitized: true };
    Object.defineProperty(accessorPayload, 'prompt', {
      enumerable: true,
      get() {
        accessorReadCount += 1;
        return SYNTHETIC_SANITIZED_PROMPT;
      },
    });
    const accessorPayloadResult = await routeInference(accessorPayload, {
      mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
      hybridExecutor: blockedCloudExecutor,
    });

    const sensitiveSystemInstructionResult = await routeInference(
      { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        systemInstruction: 'password=synthetic-not-a-secret',
        hybridExecutor: blockedCloudExecutor,
      }
    );

    const secretOutputFirewall = {
      validateCloudPayload: async () => ({
        allowed: true,
        sanitizedPrompt: 'password=synthetic-not-a-secret',
      }),
    };
    const sensitiveFirewallOutputResult = await routeInference(
      { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        privacyFirewall: secretOutputFirewall,
        hybridExecutor: blockedCloudExecutor,
      }
    );

    const changingPayload = {
      prompt: SYNTHETIC_SANITIZED_PROMPT,
      sanitized: true,
    };
    const changingPayloadFirewall = {
      validateCloudPayload: async () => {
        changingPayload.prompt = 'Modified after initial validation';
        return {
          allowed: true,
          sanitizedPrompt: SYNTHETIC_SANITIZED_PROMPT,
        };
      },
    };
    const changedPayloadResult = await routeInference(changingPayload, {
      mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
      privacyFirewall: changingPayloadFirewall,
      hybridExecutor: blockedCloudExecutor,
    });

    const consentChangingPayload = {
      prompt: SYNTHETIC_SANITIZED_PROMPT,
      sanitized: true,
    };
    const changedDuringConsentResult = await routeInference(
      consentChangingPayload,
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        consentHandler: async () => {
          consentChangingPayload.prompt = 'Modified during consent';
          return true;
        },
        hybridExecutor: blockedCloudExecutor,
      }
    );

    let observedSystemInstruction;
    const mutableCloudOptions = {
      mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
      systemInstruction: 'Synthetic, approved analysis instructions.',
      privacyFirewall: {
        validateCloudPayload: async () => {
          mutableCloudOptions.systemInstruction =
            'password=synthetic-not-a-secret';
          return {
            allowed: true,
            sanitizedPrompt: SYNTHETIC_SANITIZED_PROMPT,
          };
        },
      },
      hybridExecutor: async (_prompt, executionOptions) => {
        observedSystemInstruction = executionOptions.systemInstruction;
        return {
          text: 'Mock response.',
          model: 'mock-model',
          inferenceSource: 'in_cloud',
        };
      },
    };
    const mutableCloudOptionsResult = await routeInference(
      { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
      mutableCloudOptions
    );

    const noReuseConsentResult = await routeInference(
      { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        hybridExecutor: mockedCloudExecutor,
      }
    );
    const secondFreshConsentResult = await routeInference(
      { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
      {
        mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
        hybridExecutor: mockedCloudExecutor,
      }
    );

    const essentialSecurityResult = await routeInference(
      { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
      { mode: OPERATING_MODES.ESSENTIAL_SECURITY }
    );

    const missingAdapterError = (() => {
      try {
        createOnDeviceOnlyAI(
          { chromeAdapterFactory: () => undefined },
          {},
          {}
        );
        return null;
      } catch (error) {
        return error;
      }
    })();

    const pinnedAdapter = {
      mode: InferenceMode.ONLY_ON_DEVICE,
      isAvailable: async () => true,
      generateContent: async () => ({ text: 'not executed' }),
      downloadIfAvailable: async () => 'available',
    };
    let adapterFactoryCalls = 0;
    const pinnedAI = createOnDeviceOnlyAI(
      {
        chromeAdapterFactory: (mode) => {
          adapterFactoryCalls += 1;
          return mode === InferenceMode.ONLY_ON_DEVICE
            ? pinnedAdapter
            : undefined;
        },
      },
      {},
      {}
    );
    const pinnedAdapterIsReused =
      pinnedAI.chromeAdapterFactory() === pinnedAdapter &&
      adapterFactoryCalls === 1;

    const checks = [
      assertTest(
        missingFirewallResult.code ===
          'hybridRouter/privacy-firewall-unavailable',
        'cloud blocks without a privacy firewall'
      ),
      assertTest(
        booleanConsentResult.code ===
          'hybridRouter/consent-handler-unavailable',
        'boolean consent cannot authorize cloud inference'
      ),
      assertTest(
        rawPayloadResult.code === 'hybridRouter/raw-data-prohibited',
        'raw/confidential payload is rejected'
      ),
      assertTest(
        credentialPayloadResult.code ===
          'hybridRouter/raw-data-prohibited',
        'credential fields are rejected'
      ),
      assertTest(
        rawLogsResult.code === 'hybridRouter/raw-data-prohibited',
        'raw logs are rejected'
      ),
      assertTest(
        accessorPayloadResult.code === 'hybridRouter/invalid-payload' &&
          accessorReadCount === 0,
        'accessor payloads are rejected without invoking getters'
      ),
      assertTest(
        sensitiveSystemInstructionResult.code ===
          'hybridRouter/raw-data-prohibited',
        'sensitive system instructions are rejected'
      ),
      assertTest(
        sensitiveFirewallOutputResult.code ===
          'hybridRouter/sensitive-output-blocked',
        'sensitive firewall output is rejected'
      ),
      assertTest(
        changedPayloadResult.code === 'hybridRouter/payload-changed',
        'mutation after validation is rejected'
      ),
      assertTest(
        changedDuringConsentResult.code === 'hybridRouter/payload-changed',
        'mutation during consent is rejected'
      ),
      assertTest(
        noReuseConsentResult.ok &&
          secondFreshConsentResult.ok &&
          consentCalls === 3,
        'consent handler is called for each exact payload'
      ),
      assertTest(
        mutableCloudOptionsResult.ok &&
          observedSystemInstruction ===
            'Synthetic, approved analysis instructions.',
        'cloud options remain the validated snapshot after caller mutation'
      ),
      assertTest(
        essentialSecurityResult.ok &&
          essentialSecurityResult.inferenceSource === 'rule_engine',
        'essential-security mode uses the rule engine'
      ),
      assertTest(
        missingAdapterError?.code === 'localAI/local-only-unavailable',
        'missing ONLY_ON_DEVICE adapter is rejected before inference'
      ),
      assertTest(
        pinnedAdapterIsReused,
        'verified ONLY_ON_DEVICE adapter is pinned into the model factory'
      ),
      assertTest(
        blockedCloudInvocationCount === 0,
        'blocked requests never reach cloud-capable executors'
      ),
      assertTest(
        mockedCloudInvocationCount === 2,
        'approved test requests reach only the mock executor'
      ),
    ];

    let cloudAssistedRuntimeResult = null;
    if (options.runLiveCloudTest === true) {
      cloudAssistedRuntimeResult = await routeInference(
        { prompt: SYNTHETIC_SANITIZED_PROMPT, sanitized: true },
        {
          mode: OPERATING_MODES.CLOUD_ASSISTED_AI,
          privacyFirewall: DEV_SYNTHETIC_ONLY_FIREWALL,
          consentHandler: () => true,
          generationConfig: { maxOutputTokens: 200 },
        }
      );
    }

    const summary = {
      ok: checks.every((check) => check.passed),
      blockedCloudInvocationCount,
      mockedCloudInvocationCount,
      consentCalls,
      unitPolicyTests: checks,
      runtimeTests: {
        cloudAssistedAI: cloudAssistedRuntimeResult,
      },
    };

    console.info('[HybridRouter DevTest]', {
      ok: summary.ok,
      unitPolicyTestCount: checks.length,
      blockedCloudInvocationCount,
      mockedCloudInvocationCount,
      liveCloudTest: options.runLiveCloudTest === true ? 'requested' : 'skipped',
    });
    return summary;
  } finally {
    if (networkMockInstalled) {
      if (onlineDescriptor) {
        Object.defineProperty(navigator, 'onLine', onlineDescriptor);
      } else {
        delete navigator.onLine;
      }
    }
    restoreConsent();
    restoreRuleEngine();
    restoreFirewall();
  }
}

if (
  import.meta.env.DEV &&
  !import.meta.env.PROD &&
  typeof window !== 'undefined'
) {
  window.__veiltraceHybridRouterStatus = runHybridRouterStatusTest;
  window.__veiltraceHybridRouterTest = runHybridRouterDevTest;
}
