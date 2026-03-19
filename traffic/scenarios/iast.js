import http from 'k6/http';
import { sleep } from 'k6';
import encoding from 'k6/encoding';

const HOST = `http://${__ENV.TARGET_HOST || 'localhost'}:${__ENV.TARGET_PORT || '8080'}`;

const BACKENDS = ['/py', '/node', '/java', '/php'];

function randomBackend() {
    return BACKENDS[Math.floor(Math.random() * BACKENDS.length)];
}

export const options = {
    scenarios: {
        iast_traffic: {
            executor: 'constant-arrival-rate',
            rate: 4,
            timeUnit: '1m',
            duration: '24h',
            preAllocatedVUs: 1,
            maxVUs: 2,
        },
    },
};

// IAST-specific: tainted data that flows through vulnerable code paths (source-to-sink)
// These are designed to trigger IAST detection of real vulnerability patterns,
// not just WAF pattern matching.

export default function () {
    const prefix = randomBackend();

    // Tainted input flowing to SQL query (source: query param, sink: SQL exec)
    // Use values that look like normal input but contain SQL metacharacters
    http.get(`${HOST}${prefix}/search?q=dog' AND '1'='1`);
    sleep(1);

    // Tainted input in login form (source: form body, sink: SQL exec)
    http.post(`${HOST}${prefix}/login`, {
        username: "admin' OR '1'='1",
        password: "anything",
    });
    sleep(1);

    // Numeric injection (source: URL path, sink: SQL exec)
    http.get(`${HOST}${prefix}/product/1;SELECT pg_sleep(0)`);
    sleep(1);

    // Tainted input to file system (source: form body, sink: file write)
    const fileContent = new Uint8Array([73, 65, 83, 84]).buffer;
    const formData = {
        filename: '../../tmp/iast-test.txt',
        file: http.file(fileContent, 'test.txt'),
    };
    http.post(`${HOST}${prefix}/upload`, formData);
    sleep(1);

    // Tainted input to command execution (source: query param, sink: shell exec)
    http.get(`${HOST}${prefix}/export?file=test.txt; echo iast-probe`);
    sleep(1);

    // Tainted input to URL fetch (source: request body, sink: HTTP request)
    http.post(`${HOST}${prefix}/webhook`, JSON.stringify({
        url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    }), { headers: { 'Content-Type': 'application/json' } });
    sleep(1);

    // Tainted input to deserialization (source: form body, sink: deserialize)
    // Base64-encoded benign Python dict / JS object / PHP array
    const cartPayloads = {
        '/py': encoding.b64encode('{"items": [1, 2, 3], "total": 42.99}'),
        '/node': encoding.b64encode('({"items": [1, 2, 3], "total": 42.99})'),
        '/java': encoding.b64encode('test-payload'),
        '/php': encoding.b64encode('a:2:{s:5:"items";a:3:{i:0;i:1;i:1;i:2;i:2;i:3;}s:5:"total";d:42.99;}'),
    };
    http.post(`${HOST}${prefix}/cart/restore`, JSON.stringify({
        cart_data: cartPayloads[prefix] || cartPayloads['/py'],
    }), { headers: { 'Content-Type': 'application/json' } });
    sleep(1);

    // Review with tainted body (source: form body, sink: stored in DB and rendered)
    http.post(`${HOST}${prefix}/review`, {
        product_id: String(Math.floor(Math.random() * 8) + 1),
        username: 'iast-probe',
        rating: '4',
        body: 'Great product! <b>bold test</b> with user input',
    });
    sleep(2);

    // Profile with tainted username (source: URL path, sink: template render)
    http.get(`${HOST}${prefix}/profile/test-user<b>probe</b>`);
    sleep(2);
}
