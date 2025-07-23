class ScanProgressTracker {
    constructor(scanId) {
        this.scanId = scanId;
        this.progressBar = document.querySelector('.progress-bar');
        this.statusText = document.querySelector('.status-text');
        this.isTracking = false;
    }

    async startTracking() {
        this.isTracking = true;
        while (this.isTracking) {
            try {
                const response = await fetch(`/api/scan-progress/${this.scanId}`);
                if (!response.ok) {
                    throw new Error('Failed to fetch progress');
                }
                
                const data = await response.json();
                
                // Update progress bar
                if (this.progressBar) {
                    this.progressBar.style.width = `${data.progress}%`;
                    this.progressBar.setAttribute('aria-valuenow', data.progress);
                }

                // Update status text
                if (this.statusText) {
                    this.statusText.textContent = data.stage;
                }

                // Check if scan is complete or failed
                if (data.status === 'completed') {
                    this.isTracking = false;
                    alert('Scan completed successfully!');
                    window.location.reload(); // Refresh page to show results
                } else if (data.status === 'failed') {
                    this.isTracking = false;
                    alert('Scan failed. Please try again.');
                }

                // Wait before next update
                await new Promise(resolve => setTimeout(resolve, 1000));
            } catch (error) {
                console.error('Error tracking progress:', error);
                this.isTracking = false;
            }
        }
    }

    stopTracking() {
        this.isTracking = false;
    }
}

// Function to start scan and track progress
async function startScanWithProgress(url, scanType) {
    try {
        // Start the scan
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url, scanType })
        });

        if (!response.ok) {
            throw new Error('Failed to start scan');
        }

        const data = await response.json();
        
        // Initialize progress tracker
        const progressTracker = new ScanProgressTracker(data.scanId);
        progressTracker.startTracking();

    } catch (error) {
        console.error('Error starting scan:', error);
        alert('Failed to start scan. Please try again.');
    }
} 