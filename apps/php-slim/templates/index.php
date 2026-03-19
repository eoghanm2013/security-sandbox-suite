<?php include __DIR__ . '/header.php'; ?>
<h1>Welcome to Bits &amp; Bytes Pet Shop</h1>
<p style="color:var(--dd-text-light);margin-bottom:1rem;">Datadog-themed pet supplies for the discerning pup. Browse our collection below.</p>

<form action="<?= htmlspecialchars($prefix ?? '') ?>/search" method="get" class="search-bar">
    <input type="text" name="q" placeholder="Search products...">
    <button type="submit" class="btn">Search</button>
</form>

<div class="product-grid">
    <?php foreach ($products as $p): ?>
    <a href="<?= htmlspecialchars($prefix ?? '') ?>/product/<?= (int) $p['id'] ?>" style="text-decoration:none;color:inherit;">
        <div class="product-card">
            <div class="emoji"><?= htmlspecialchars($p['image_emoji'] ?? '') ?></div>
            <span class="category"><?= htmlspecialchars($p['category'] ?? '') ?></span>
            <h3><?= htmlspecialchars($p['name'] ?? '') ?></h3>
            <span class="price">$<?= number_format((float) ($p['price'] ?? 0), 2) ?></span>
        </div>
    </a>
    <?php endforeach; ?>
</div>
<?php include __DIR__ . '/footer.php'; ?>
