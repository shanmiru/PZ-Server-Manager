function hostnameToIpv4(hostname) {
    return new Promise((resolve, reject) => {
        // Using public DNS resolution API
        fetch(`https://dns.google/resolve?name=${hostname}`)
            .then(response => response.json())
            .then(data => {
                if (data.Answer && data.Answer.length > 0) {
                    // Find A records (IPv4)
                    const ipv4Record = data.Answer.find(record => record.type === 1);
                    if (ipv4Record) {
                        resolve(ipv4Record.data);
                    } else {
                        reject(new Error('No IPv4 address found'));
                    }
                } else {
                    reject(new Error('DNS resolution failed'));
                }
            })
            .catch(error => {
                reject(error);
            });
    });
}

function updateServerIpDisplay(className) {
    // Find all elements with the specified class
    const serverIpElements = document.getElementsByClassName(className);

    Array.from(serverIpElements).forEach(element => {
        const hostname = element.textContent.trim();

        // Check if it's a hostname (not an IP address)
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
            // Convert hostname to IP
            hostnameToIpv4(hostname)
                .then(ipAddress => {
                    // Update the display with IP address
                    element.textContent = ipAddress;
                    // Optionally keep the hostname as a tooltip
                    element.setAttribute('title', `Hostname: ${hostname}`);
                })
                .catch(error => {
                    console.error(`Failed to resolve ${hostname}: ${error.message}`);
                    // Keep the hostname if resolution fails
                });
        }
    });
}