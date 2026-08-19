import http from 'k6/http';
import { check, sleep } from 'k6';
import { profiles } from '../config/profiles.js';
import { thresholdsFromEnvironment } from '../config/thresholds.js';

const profileName = __ENV.TEST_PROFILE || 'smoke';
const selectedProfile = profiles[profileName];

if (!selectedProfile) {
  throw new Error(`Unknown TEST_PROFILE: ${profileName}`);
}

const targetUrl = (__ENV.TARGET_URL || 'http://127.0.0.1:8080').replace(/\/$/, '');
const targetPath = __ENV.TARGET_PATH || '/healthz';

export const options = {
  scenarios: {
    [profileName]: selectedProfile,
  },
  thresholds: thresholdsFromEnvironment(__ENV),
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  const response = http.get(`${targetUrl}${targetPath}`, {
    tags: { profile: profileName, endpoint: targetPath },
    timeout: __ENV.REQUEST_TIMEOUT || '5s',
  });

  check(response, {
    'status is successful': (result) => result.status >= 200 && result.status < 400,
    'correlation id is present when required': (result) =>
      (__ENV.REQUIRE_CORRELATION_ID || 'false') !== 'true' ||
      Boolean(result.headers['X-Correlation-Id']),
  });

  sleep(Number(__ENV.ITERATION_SLEEP_SECONDS || '1'));
}
