<?php include __DIR__ . '/header.php'; ?>
<div class="card">
    <div style="display:flex;gap:2rem;align-items:flex-start;">
        <div style="font-size:5rem;background:var(--dd-gray-light);padding:1.5rem;border-radius:8px;"><?= htmlspecialchars($product['image_emoji'] ?? '') ?></div>
        <div style="flex:1;">
            <span class="category" style="color:var(--dd-text-light);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;"><?= htmlspecialchars($product['category'] ?? '') ?></span>
            <h1 style="margin-top:.25rem;"><?= htmlspecialchars($product['name'] ?? '') ?></h1>
            <p class="price" style="color:var(--dd-purple);font-weight:700;font-size:1.5rem;margin:.5rem 0;">$<?= number_format((float) ($product['price'] ?? 0), 2) ?></p>
            <p style="color:var(--dd-text-light);"><?= htmlspecialchars($product['description'] ?? '') ?></p>
            <p style="margin-top:.5rem;font-size:.85rem;color:var(--dd-text-light);">In stock: <?= (int) ($product['stock'] ?? 0) ?></p>
        </div>
    </div>
</div>

<div class="card">
    <h2>Reviews</h2>
    <?php foreach ($reviews ?? [] as $r): ?>
    <div class="review">
        <div class="meta">
            <span class="stars"><?= str_repeat('★', (int) ($r['rating'] ?? 0)) ?><?= str_repeat('☆', 5 - (int) ($r['rating'] ?? 0)) ?></span>
            &middot; <strong><?= htmlspecialchars($r['username'] ?? '') ?></strong> &middot; <?= htmlspecialchars($r['created_at'] ?? '') ?>
        </div>
        <?php /* VULNERABLE: Stored XSS - body rendered without htmlspecialchars */ ?>
        <p><?= $r['body'] ?? '' ?></p>
    </div>
    <?php endforeach; ?>
    <?php if (empty($reviews)): ?>
    <p style="color:var(--dd-text-light);">No reviews yet. Be the first!</p>
    <?php endif; ?>

    <hr style="margin:1.5rem 0;border:none;border-top:1px solid #E9E0F5;">
    <h2>Write a Review</h2>
    <form action="<?= htmlspecialchars($prefix ?? '') ?>/review" method="post">
        <input type="hidden" name="product_id" value="<?= (int) ($product['id'] ?? 0) ?>">
        <div class="form-group">
            <label>Your Name</label>
            <input type="text" name="username" placeholder="anonymous" value="<?= htmlspecialchars($session['user'] ?? '') ?>">
        </div>
        <div class="form-group">
            <label>Rating</label>
            <select name="rating">
                <option value="5">★★★★★</option>
                <option value="4">★★★★☆</option>
                <option value="3">★★★☆☆</option>
                <option value="2">★★☆☆☆</option>
                <option value="1">★☆☆☆☆</option>
            </select>
        </div>
        <div class="form-group">
            <label>Review</label>
            <textarea name="body" rows="3" placeholder="Write your review..."></textarea>
        </div>
        <button type="submit" class="btn">Submit Review</button>
    </form>
</div>
<?php include __DIR__ . '/footer.php'; ?>
