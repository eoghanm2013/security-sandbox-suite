<?php include __DIR__ . '/header.php'; ?>
<div style="max-width:400px;margin:2rem auto;">
    <div class="card">
        <h1>Login</h1>
        <?php if (!empty($error)): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <form action="<?= htmlspecialchars($prefix ?? '') ?>/login" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="username" autofocus>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="password">
            </div>
            <button type="submit" class="btn" style="width:100%;">Login</button>
        </form>
        <p style="margin-top:1rem;font-size:.85rem;color:var(--dd-text-light);">
            Test accounts: admin/admin123, testuser/password, bits/woof2024
        </p>
    </div>
</div>
<?php include __DIR__ . '/footer.php'; ?>
