import http from "k6/http";
import { check } from "k6";

export const options = {
  scenarios: {
    smoke: {
      executor: "shared-iterations",
      vus: 1,
      iterations: 1,
      maxDuration: "10s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<=0.01"],
    http_req_duration: ["p(95)<=1000"],
  },
};

export default function () {
  const response = http.get(`${__ENV.QUALIFICATION_TARGET}/healthz`);
  check(response, { "status is 200": (result) => result.status === 200 });
}
