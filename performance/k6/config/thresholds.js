export function thresholdsFromEnvironment(environment) {
  return {
    http_req_failed: [`rate<${environment.MAX_ERROR_RATE || '0.01'}`],
    http_req_duration: [
      `p(50)<${environment.MAX_P50_MS || '200'}`,
      `p(95)<${environment.MAX_P95_MS || '500'}`,
      `p(99)<${environment.MAX_P99_MS || '1000'}`,
    ],
    checks: [`rate>${environment.MIN_CHECK_RATE || '0.99'}`],
  };
}
