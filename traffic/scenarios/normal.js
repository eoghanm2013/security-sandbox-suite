import http from 'k6/http';
import { sleep, check } from 'k6';

const HOST = `http://${__ENV.TARGET_HOST || 'localhost'}:${__ENV.TARGET_PORT || '8080'}`;

const BACKENDS = ['/py', '/node', '/java', '/php'];

function randomBackend() {
    return BACKENDS[Math.floor(Math.random() * BACKENDS.length)];
}

export const options = {
    scenarios: {
        normal_browsing: {
            executor: 'constant-arrival-rate',
            rate: 2,
            timeUnit: '1m',
            duration: '24h',
            preAllocatedVUs: 1,
            maxVUs: 2,
        },
    },
};

export default function () {
    const prefix = randomBackend();

    // Browse homepage
    let res = http.get(`${HOST}${prefix}/`);
    check(res, { 'homepage 200': (r) => r.status === 200 });
    sleep(1);

    // Search for a product
    const queries = ['chew', 'collar', 'ball', 'leash', 'treats', 'bed', 'bell', 'action'];
    const q = queries[Math.floor(Math.random() * queries.length)];
    res = http.get(`${HOST}${prefix}/search?q=${q}`);
    check(res, { 'search 200': (r) => r.status === 200 });
    sleep(0.5);

    // View a random product
    const productId = Math.floor(Math.random() * 8) + 1;
    res = http.get(`${HOST}${prefix}/product/${productId}`);
    check(res, { 'product 200': (r) => r.status === 200 });
    sleep(0.5);

    // View a profile
    const users = ['admin', 'testuser', 'bits'];
    const user = users[Math.floor(Math.random() * users.length)];
    res = http.get(`${HOST}${prefix}/profile/${user}`);
    check(res, { 'profile 200': (r) => r.status === 200 });
    sleep(0.5);

    // Login attempt
    res = http.post(`${HOST}${prefix}/login`, {
        username: 'testuser',
        password: 'password',
    });
    check(res, { 'login ok': (r) => r.status === 200 || r.status === 302 });
    sleep(0.5);

    // Health check
    res = http.get(`${HOST}${prefix}/health`);
    check(res, { 'health 200': (r) => r.status === 200 });
    sleep(2);
}
