// Check if we just arrived from login
document.addEventListener('DOMContentLoaded', function() {
    // If we're on the dashboard and just came from login
    if (window.location.pathname.includes('/dashboard') && localStorage.getItem('loginAttempted')) {
        console.log('New login detected on dashboard, refreshing assets...');
        
        // Clear the flag
        localStorage.removeItem('loginAttempted');
        
        // Set a cache-busting parameter for all resources
        const timestamp = new Date().getTime();
        
        // Refresh CSS
        document.querySelectorAll('link[rel="stylesheet"]').forEach(function(link) {
            const href = link.getAttribute('href');
            if (href && !href.includes('bootstrap')) { // Don't modify CDN resources
                link.setAttribute('href', href.split('?')[0] + '?v=' + timestamp);
            }
        });
        
        // Refresh JS
        document.querySelectorAll('script[src]').forEach(function(script) {
            const src = script.getAttribute('src');
            if (src && !src.includes('bootstrap')) { // Don't modify CDN resources
                script.setAttribute('src', src.split('?')[0] + '?v=' + timestamp);
            }
        });
        
        // Refresh images
        document.querySelectorAll('img').forEach(function(img) {
            const src = img.getAttribute('src');
            if (src && !src.includes('bootstrap')) {
                img.setAttribute('src', src.split('?')[0] + '?v=' + timestamp);
            }
        });
    }
});