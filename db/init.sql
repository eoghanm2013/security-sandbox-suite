-- Bits & Bytes Pet Shop - Database Schema
-- Intentionally uses patterns that enable SQL injection testing

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,  -- plaintext passwords (SAST finding)
    email VARCHAR(200),
    role VARCHAR(20) DEFAULT 'customer',
    api_key VARCHAR(64),             -- hardcoded API keys (SAST finding)
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category VARCHAR(100),
    stock INTEGER DEFAULT 100,
    image_emoji VARCHAR(10) DEFAULT '🐾',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id),
    user_id INTEGER REFERENCES users(id),
    username VARCHAR(100),
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    body TEXT,  -- stored as-is, enables XSS
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total DECIMAL(10,2),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cart_items (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Seed users (plaintext passwords = SAST finding)
INSERT INTO users (username, password, email, role, api_key) VALUES
    ('admin', 'admin123', 'admin@bitsbytes.pet', 'admin', 'sk_live_BITSANDBYTES_ADMIN_KEY_DO_NOT_SHARE'),
    ('testuser', 'password', 'test@bitsbytes.pet', 'customer', NULL),
    ('bits', 'woof2024', 'bits@example.com', 'customer', NULL),
    ('warehouse', 'shipping99', 'warehouse@bitsbytes.pet', 'staff', 'sk_live_WAREHOUSE_INTERNAL_KEY');

-- Seed products (Datadog-themed pet supplies)
INSERT INTO products (name, description, price, category, stock, image_emoji) VALUES
    ('Bits Chew Toy', 'The official Datadog mascot chew toy. Durable rubber, squeaks on every bite. Your pup will love monitoring this toy all day.', 12.99, 'toys', 150, '🦴'),
    ('Purple Paws Collar', 'Premium leather collar in Datadog purple (#632CA6). Adjustable fit, reflective stitching for night walks. Available in S/M/L.', 24.99, 'accessories', 80, '🐕'),
    ('Agent Fetch Ball', 'Bouncy tennis ball branded with the Datadog Agent logo. Tracks itself across the yard (disclaimer: not really).', 8.99, 'toys', 200, '🎾'),
    ('Trace-able Leash', 'A 6ft retractable leash with distributed tracing built in. Follow every path your dog takes on walkies.', 19.99, 'accessories', 60, '🦮'),
    ('Monitor Treats (32oz)', 'All-natural dog treats for continuous monitoring of tail-wag metrics. Chicken flavor. No artificial alerting agents.', 15.99, 'food', 300, '🍖'),
    ('APM Action Figure', 'Collectible Bits action figure wearing an APM cape. Detects performance issues in your living room.', 29.99, 'merchandise', 45, '🧸'),
    ('Dashboard Dog Bed', 'Memory foam dog bed with a printed dashboard pattern. Your dog can sleep on top of your SLOs.', 89.99, 'beds', 25, '🛏️'),
    ('Alerting Bell Toy', 'Jingle bell toy that alerts you every time your dog plays with it. Configurable thresholds not included.', 6.99, 'toys', 180, '🔔');
