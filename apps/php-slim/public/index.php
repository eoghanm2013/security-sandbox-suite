<?php

declare(strict_types=1);

// SAST findings: hardcoded credentials
define('SECRET_KEY', 'BITS_AND_BYTES_SUPER_SECRET_KEY_2024');
define('INTERNAL_API_TOKEN', 'sk_live_dd_internal_api_token_never_commit');

use DI\ContainerBuilder;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Slim\Views\PhpRenderer;

require __DIR__ . '/../vendor/autoload.php';

session_start();

$TRACER = 'dd-trace-php';
$VERSION = 'latest';

function getDb(): PDO
{
    $url = getenv('DATABASE_URL') ?: 'postgresql://petshop:petshop123@localhost:5432/petshop';
    $parts = parse_url($url);
    $host = $parts['host'] ?? 'localhost';
    $port = $parts['port'] ?? 5432;
    $dbname = ltrim($parts['path'] ?? '/petshop', '/');
    $user = $parts['user'] ?? 'petshop';
    $pass = $parts['pass'] ?? '';
    $dsn = sprintf('pgsql:host=%s;port=%s;dbname=%s', $host, $port, $dbname);
    return new PDO($dsn, $user, $pass);
}

$containerBuilder = new ContainerBuilder();
$containerBuilder->addDefinitions([
    PhpRenderer::class => function () {
        return new PhpRenderer(__DIR__ . '/../templates');
    },
    'renderer' => \DI\get(PhpRenderer::class),
]);
$container = $containerBuilder->build();
AppFactory::setContainer($container);
$app = AppFactory::create();

$app->addBodyParsingMiddleware();

$app->add(function (Request $request, $handler) {
    $GLOBALS['url_prefix'] = $request->getHeaderLine('X-Forwarded-Prefix') ?: '';
    return $handler->handle($request);
});

$app->get('/', function (Request $request, Response $response) use ($TRACER, $VERSION) {
    $db = getDb();
    $stmt = $db->query('SELECT * FROM products ORDER BY id');
    $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $renderer = $this->get('renderer');
    return $renderer->render($response, 'index.php', [
        'products' => $products,
        'title' => 'Bits & Bytes Pet Shop',
        'tracer' => $TRACER,
        'version' => $VERSION,
        'prefix' => $GLOBALS['url_prefix'] ?? '',
    ]);
});

$app->get('/search', function (Request $request, Response $response) use ($TRACER, $VERSION) {
    $params = $request->getQueryParams();
    $q = $params['q'] ?? '';
    $results = [];
    $error = null;
    if ($q !== '') {
        $db = getDb();
        $sql = "SELECT * FROM products WHERE name ILIKE '%{$q}%' OR description ILIKE '%{$q}%'";
        try {
            $stmt = $db->query($sql);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }
    }
    $renderer = $this->get('renderer');
    return $renderer->render($response, 'search.php', [
        'q' => $q,
        'results' => $results,
        'error' => $error,
        'title' => 'Search - Bits & Bytes',
        'tracer' => $TRACER,
        'version' => $VERSION,
        'prefix' => $GLOBALS['url_prefix'] ?? '',
    ]);
});

$app->get('/login', function (Request $request, Response $response) use ($TRACER, $VERSION) {
    $renderer = $this->get('renderer');
    return $renderer->render($response, 'login.php', [
        'error' => null,
        'title' => 'Login - Bits & Bytes',
        'tracer' => $TRACER,
        'version' => $VERSION,
        'prefix' => $GLOBALS['url_prefix'] ?? '',
    ]);
});

$app->post('/login', function (Request $request, Response $response) use ($TRACER, $VERSION) {
    $params = $request->getParsedBody() ?? [];
    $username = $params['username'] ?? '';
    $password = $params['password'] ?? '';
    $error = null;
    $db = getDb();
    $sql = "SELECT * FROM users WHERE username='{$username}' AND password='{$password}'";
    try {
        $stmt = $db->query($sql);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            $_SESSION['user'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            $prefix = $GLOBALS['url_prefix'] ?? '';
            return $response->withHeader('Location', $prefix . '/')->withStatus(302);
        }
        $error = 'Invalid username or password';
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
    $renderer = $this->get('renderer');
    return $renderer->render($response, 'login.php', [
        'error' => $error,
        'title' => 'Login - Bits & Bytes',
        'tracer' => $TRACER,
        'version' => $VERSION,
        'prefix' => $GLOBALS['url_prefix'] ?? '',
    ]);
});

$app->get('/logout', function (Request $request, Response $response) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    $prefix = $GLOBALS['url_prefix'] ?? '';
    return $response->withHeader('Location', $prefix . '/')->withStatus(302);
});

$app->get('/product/{id}', function (Request $request, Response $response, array $args) use ($TRACER, $VERSION) {
    $id = $args['id'];
    $db = getDb();
    $sql = "SELECT * FROM products WHERE id = {$id}";
    try {
        $stmt = $db->query($sql);
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        $renderer = $this->get('renderer');
        return $renderer->render($response->withStatus(400), 'error.php', [
            'error' => $e->getMessage(),
            'title' => 'Error - Bits & Bytes',
            'tracer' => $TRACER,
            'version' => $VERSION,
            'prefix' => $GLOBALS['url_prefix'] ?? '',
        ]);
    }
    if (!$product) {
        $renderer = $this->get('renderer');
        return $renderer->render($response->withStatus(404), 'error.php', [
            'error' => 'Product not found',
            'title' => 'Error - Bits & Bytes',
            'tracer' => $TRACER,
            'version' => $VERSION,
            'prefix' => $GLOBALS['url_prefix'] ?? '',
        ]);
    }
    $stmt = $db->prepare('SELECT * FROM reviews WHERE product_id = ? ORDER BY created_at DESC');
    $stmt->execute([$product['id']]);
    $reviews = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $renderer = $this->get('renderer');
    return $renderer->render($response, 'product.php', [
        'product' => $product,
        'reviews' => $reviews,
        'session' => $_SESSION,
        'title' => $product['name'] . ' - Bits & Bytes',
        'tracer' => $TRACER,
        'version' => $VERSION,
        'prefix' => $GLOBALS['url_prefix'] ?? '',
    ]);
});

$app->post('/review', function (Request $request, Response $response) {
    $params = $request->getParsedBody() ?? [];
    $productId = $params['product_id'] ?? '';
    $username = $params['username'] ?? 'anonymous';
    $rating = $params['rating'] ?? '5';
    $body = $params['body'] ?? '';
    $db = getDb();
    $stmt = $db->prepare('INSERT INTO reviews (product_id, username, rating, body) VALUES (?, ?, ?, ?)');
    $stmt->execute([$productId, $username, $rating, $body]);
    $prefix = $GLOBALS['url_prefix'] ?? '';
    return $response->withHeader('Location', $prefix . '/product/' . $productId)->withStatus(302);
});

$app->get('/profile/{username}', function (Request $request, Response $response, array $args) use ($TRACER, $VERSION) {
    $username = $args['username'];
    $db = getDb();
    $stmt = $db->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $renderer = $this->get('renderer');
    return $renderer->render($response, 'profile.php', [
        'username' => $username,
        'user' => $user,
        'title' => $username . ' - Bits & Bytes',
        'tracer' => $TRACER,
        'version' => $VERSION,
        'prefix' => $GLOBALS['url_prefix'] ?? '',
    ]);
});

$app->post('/upload', function (Request $request, Response $response) {
    $files = $request->getUploadedFiles();
    $uploadedFile = $files['file'] ?? null;
    if (!$uploadedFile || $uploadedFile->getError() !== UPLOAD_ERR_OK) {
        $response->getBody()->write(json_encode(['error' => 'No file provided']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    $params = $request->getParsedBody() ?? [];
    $filename = $params['filename'] ?? $uploadedFile->getClientFilename();
    $savePath = '/tmp/uploads/' . $filename;
    if (!is_dir('/tmp/uploads')) {
        mkdir('/tmp/uploads', 0755, true);
    }
    $uploadedFile->moveTo($savePath);
    $response->getBody()->write(json_encode(['message' => 'Saved to ' . $savePath, 'filename' => $filename]));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->post('/webhook', function (Request $request, Response $response) {
    $params = $request->getParsedBody();
    $url = null;
    if (is_array($params) && isset($params['url'])) {
        $url = $params['url'];
    } else {
        $body = (string) $request->getBody();
        $json = json_decode($body, true);
        $url = $json['url'] ?? '';
    }
    if (empty($url)) {
        $response->getBody()->write(json_encode(['error' => 'url required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    try {
        $content = file_get_contents($url);
        $data = is_string($content) ? mb_substr($content, 0, 2000) : '';
        $response->getBody()->write(json_encode(['status' => 200, 'body' => $data]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (Throwable $e) {
        $response->getBody()->write(json_encode(['error' => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(502);
    }
});

$app->get('/export', function (Request $request, Response $response) {
    $params = $request->getQueryParams();
    $filename = $params['file'] ?? '';
    if ($filename === '') {
        $response->getBody()->write(json_encode(['error' => 'file parameter required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    try {
        $output = shell_exec("cat /tmp/uploads/{$filename}");
        $response->getBody()->write($output ?? '');
        return $response->withHeader('Content-Type', 'text/plain');
    } catch (Throwable $e) {
        $response->getBody()->write(json_encode(['error' => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

$app->post('/cart/restore', function (Request $request, Response $response) {
    $params = $request->getParsedBody();
    $cartData = null;
    if (is_array($params) && isset($params['cart_data'])) {
        $cartData = $params['cart_data'];
    } else {
        $body = (string) $request->getBody();
        $json = json_decode($body, true);
        $cartData = $json['cart_data'] ?? '';
    }
    if (empty($cartData)) {
        $response->getBody()->write(json_encode(['error' => 'cart_data required']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    try {
        $cart = unserialize(base64_decode($cartData));
        $response->getBody()->write(json_encode(['cart' => (string) $cart]));
        return $response->withHeader('Content-Type', 'application/json');
    } catch (Throwable $e) {
        $response->getBody()->write(json_encode(['error' => $e->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
});

$app->get('/health', function (Request $request, Response $response) {
    $response->getBody()->write(json_encode([
        'status' => 'ok',
        'service' => 'petshop-php',
        'tracer' => 'dd-trace-php',
    ]));
    return $response->withHeader('Content-Type', 'application/json');
});

$app->run();
