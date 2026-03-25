import http from 'k6/http';
import { check, group } from 'k6';
import { Trend } from 'k6/metrics';

const BASE = `http://${__ENV.TARGET_HOST || 'nginx'}:${__ENV.TARGET_PORT || '80'}`;

const pyDuration = new Trend('py_req_duration', true);
const nodeDuration = new Trend('node_req_duration', true);
const javaDuration = new Trend('java_req_duration', true);
const phpDuration = new Trend('php_req_duration', true);

export const options = {
    scenarios: {
        benchmark: {
            executor: 'constant-arrival-rate',
            rate: 20,
            timeUnit: '1s',
            duration: '60s',
            preAllocatedVUs: 10,
            maxVUs: 30,
        },
    },
    thresholds: {
        http_req_duration: ['p(95)<5000'],
    },
};

const ENDPOINTS = [
    '/search?q=ball',
    '/product/1',
    '/profile/admin',
    '/login',
    '/health',
];

export default function () {
    const langs = [
        { prefix: '/py', metric: pyDuration },
        { prefix: '/node', metric: nodeDuration },
        { prefix: '/java', metric: javaDuration },
        { prefix: '/php', metric: phpDuration },
    ];

    const lang = langs[__ITER % langs.length];
    const endpoint = ENDPOINTS[Math.floor(__ITER / langs.length) % ENDPOINTS.length];
    const url = `${BASE}${lang.prefix}${endpoint}`;

    const res = http.get(url);
    lang.metric.add(res.timings.duration);

    check(res, { 'status is 200': (r) => r.status === 200 });
}
