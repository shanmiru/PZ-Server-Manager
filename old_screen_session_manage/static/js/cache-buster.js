// Add this to your dashboard.html template
document.addEventListener('DOMContentLoaded', function() {
    // Check if cache clearing is needed
    const clearCache = document.body.getAttribute('data-clear-cache') === 'true';
    
    if (clearCache) {
        console.log('Clearing cache after login');
        
        // Add timestamp to all resource URLs to force reload
        const timestamp = new Date().getTime();
        
        // Refresh CSS files
        document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
            if (link.href && !link.href.includes('cdn.jsdelivr.net')) {
                link.href = link.href.split('?')[0] + '?v=' + timestamp;
            }
        });
        
        // Refresh JS files
        document.querySelectorAll('script[src]').forEach(script => {
            if (script.src && !script.src.includes('cdn.jsdelivr.net')) {
                script.src = script.src.split('?')[0] + '?v=' + timestamp;
            }
        });
        
        // Refresh images
        document.querySelectorAll('img').forEach(img => {
            if (img.src) {
                img.src = img.src.split('?')[0] + '?v=' + timestamp;
            }
        });
    }
});