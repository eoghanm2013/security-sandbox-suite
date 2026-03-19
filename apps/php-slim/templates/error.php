<?php include __DIR__ . '/header.php'; ?>
<div class="card">
    <h1>Error</h1>
    <div class="alert alert-error"><?= htmlspecialchars($error ?? 'Unknown error') ?></div>
    <a href="/" class="btn btn-outline">Back to Home</a>
</div>
<?php include __DIR__ . '/footer.php'; ?>
