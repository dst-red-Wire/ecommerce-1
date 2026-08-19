export const profiles = {
  smoke: {
    executor: 'shared-iterations',
    vus: 1,
    iterations: 5,
    maxDuration: '30s',
  },
  baseline: {
    executor: 'constant-vus',
    vus: 5,
    duration: '2m',
  },
  load: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 10 },
      { duration: '5m', target: 10 },
      { duration: '1m', target: 0 },
    ],
  },
  stress: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '2m', target: 20 },
      { duration: '3m', target: 40 },
      { duration: '2m', target: 0 },
    ],
  },
  spike: {
    executor: 'ramping-vus',
    startVUs: 0,
    stages: [
      { duration: '30s', target: 5 },
      { duration: '15s', target: 50 },
      { duration: '1m', target: 5 },
      { duration: '30s', target: 0 },
    ],
  },
  soak: {
    executor: 'constant-vus',
    vus: 10,
    duration: '30m',
  },
};
