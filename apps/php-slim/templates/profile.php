<?php include __DIR__ . '/header.php'; ?>
<div class="card">
    <?php /* VULNERABLE: Reflected XSS - username echoed without htmlspecialchars */ ?>
    <h1>Profile: <?= $username ?></h1>
    <?php if (!empty($user)): ?>
    <p><strong>Email:</strong> <?= htmlspecialchars($user['email'] ?? '') ?></p>
    <p><strong>Role:</strong> <?= htmlspecialchars($user['role'] ?? '') ?></p>
    <p><strong>Member since:</strong> <?= htmlspecialchars($user['created_at'] ?? '') ?></p>
    <?php else: ?>
    <div class="alert alert-error">User "<?= $username ?>" not found.</div>
    <?php endif; ?>
</div>
<?php include __DIR__ . '/footer.php'; ?>
