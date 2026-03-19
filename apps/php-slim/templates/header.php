<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title ?? 'Bits &amp; Bytes Pet Shop') ?></title>
    <style>
    :root{--dd-purple:#632CA6;--dd-purple-light:#8B5CF6;--dd-purple-dark:#4A1D82;--dd-purple-bg:#F5F0FF;--dd-purple-hover:#7C3AED;--dd-green:#2ECC71;--dd-red:#E74C3C;--dd-orange:#F59E0B;--dd-gray:#6B7280;--dd-gray-light:#F3F4F6;--dd-white:#FFFFFF;--dd-text:#1F2937;--dd-text-light:#6B7280;--dd-radius:8px;--dd-shadow:0 2px 8px rgba(99,44,166,0.12)}
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--dd-purple-bg);color:var(--dd-text);line-height:1.6;min-height:100vh}
    a{color:var(--dd-purple);text-decoration:none}a:hover{text-decoration:underline}
    header{background:linear-gradient(135deg,#632CA6,#4A1D82);color:#fff;padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 12px rgba(99,44,166,.3)}
    header .brand{display:flex;align-items:center;gap:.75rem;font-size:1.25rem;font-weight:700}
    header .brand svg{width:40px;height:40px}
    header nav{display:flex;gap:1.5rem;align-items:center}
    header nav a{color:rgba(255,255,255,.85);font-weight:500;font-size:.9rem}header nav a:hover{color:#fff;text-decoration:none}
    .tracer-badge{background:rgba(255,255,255,.15);padding:.25rem .75rem;border-radius:20px;font-size:.8rem;font-weight:500}
    main{max-width:1100px;margin:2rem auto;padding:0 1.5rem}
    .product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:1.5rem;margin-top:1.5rem}
    .product-card{background:var(--dd-white);border-radius:var(--dd-radius);box-shadow:var(--dd-shadow);padding:1.25rem;border:1px solid #E9E0F5;transition:transform .15s,box-shadow .15s}
    .product-card:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(99,44,166,.18)}
    .product-card .emoji{font-size:3rem;text-align:center;padding:1rem 0;background:var(--dd-gray-light);border-radius:6px;margin-bottom:1rem}
    .product-card h3{font-size:1rem;margin-bottom:.25rem}.product-card .price{color:var(--dd-purple);font-weight:700;font-size:1.1rem}
    .product-card .category{color:var(--dd-text-light);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}
    .btn{display:inline-block;background:var(--dd-purple);color:#fff;padding:.6rem 1.25rem;border:none;border-radius:var(--dd-radius);cursor:pointer;font-size:.9rem;font-weight:600;transition:background .15s}
    .btn:hover{background:var(--dd-purple-hover);text-decoration:none;color:#fff}
    .btn-outline{background:transparent;color:var(--dd-purple);border:2px solid var(--dd-purple)}.btn-outline:hover{background:var(--dd-purple);color:#fff}
    .card{background:var(--dd-white);border-radius:var(--dd-radius);box-shadow:var(--dd-shadow);padding:1.5rem;border:1px solid #E9E0F5;margin-bottom:1.5rem}
    .form-group{margin-bottom:1rem}.form-group label{display:block;font-weight:600;margin-bottom:.35rem;font-size:.9rem}
    .form-group input,.form-group textarea,.form-group select{width:100%;padding:.6rem .75rem;border:1px solid #D1C4E9;border-radius:var(--dd-radius);font-size:.9rem}
    .form-group input:focus,.form-group textarea:focus{outline:none;border-color:var(--dd-purple);box-shadow:0 0 0 3px rgba(99,44,166,.1)}
    .search-bar{display:flex;gap:.5rem;margin-bottom:1.5rem}.search-bar input{flex:1}
    .alert{padding:.75rem 1rem;border-radius:var(--dd-radius);margin-bottom:1rem;font-size:.9rem}
    .alert-success{background:#D1FAE5;color:#065F46;border:1px solid #6EE7B7}
    .alert-error{background:#FEE2E2;color:#991B1B;border:1px solid #FCA5A5}
    .review{border-bottom:1px solid #E9E0F5;padding:1rem 0}.review:last-child{border-bottom:none}
    .review .meta{color:var(--dd-text-light);font-size:.85rem;margin-bottom:.25rem}.review .stars{color:var(--dd-orange)}
    footer{text-align:center;padding:1.5rem;color:var(--dd-text-light);font-size:.8rem;margin-top:3rem;border-top:1px solid #E9E0F5}
    footer .tracer-info{color:var(--dd-purple);font-weight:600}
    h1{font-size:1.5rem;margin-bottom:1rem;color:var(--dd-purple-dark)}h2{font-size:1.25rem;margin-bottom:.75rem;color:var(--dd-purple-dark)}
    .vuln-tag{display:inline-block;background:#FEE2E2;color:#991B1B;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600;text-transform:uppercase}
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg"><circle cx="24" cy="24" r="24" fill="rgba(255,255,255,0.15)"/><ellipse cx="24" cy="30" rx="8" ry="6" fill="white"/><circle cx="14" cy="19" r="4.5" fill="white"/><circle cx="24" cy="14" r="4.5" fill="white"/><circle cx="34" cy="19" r="4.5" fill="white"/></svg>
            <span>Bits &amp; Bytes Pet Shop</span>
        </div>
        <nav>
            <a href="<?= htmlspecialchars($prefix ?? '') ?>/">Home</a>
            <a href="<?= htmlspecialchars($prefix ?? '') ?>/search">Search</a>
            <a href="<?= htmlspecialchars($prefix ?? '') ?>/login">Login</a>
            <span class="tracer-badge"><?= htmlspecialchars($tracer ?? 'dd-trace-php') ?> <?= htmlspecialchars($version ?? 'latest') ?></span>
        </nav>
    </header>

    <main>
