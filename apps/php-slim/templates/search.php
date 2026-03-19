<?php include __DIR__ . '/header.php'; ?>
<h1>Search Products</h1>

<form action="<?= htmlspecialchars($prefix ?? '') ?>/search" method="get" class="search-bar">
    <input type="text" name="q" value="<?= htmlspecialchars($q ?? '') ?>" placeholder="Search products..." autofocus>
    <button type="submit" class="btn">Search</button>
</form>

<?php if (!empty($error)): ?>
<div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<?php if ($q !== ''): ?>
<p style="color:var(--dd-text-light);margin-bottom:1rem;"><?= count($results ?? []) ?> result(s) for "<?= htmlspecialchars($q) ?>"</p>
<?php endif; ?>

<div class="product-grid">
    <?php foreach ($results ?? [] as $p): ?>
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
