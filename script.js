class PhishingDetector {
    constructor() {
        this.history = this.loadHistory();
        this.initializeElements();
        this.attachEventListeners();
        this.renderHistory();
    }

    initializeElements() {
        this.form = document.getElementById('scanForm');
        this.urlInput = document.getElementById('urlInput');
        this.scanButton = document.getElementById('scanButton');
        this.buttonText = document.getElementById('buttonText');
        this.errorDiv = document.getElementById('error');
        this.resultDiv = document.getElementById('result');
        this.resultIcon = document.getElementById('resultIcon');
        this.resultTitle = document.getElementById('resultTitle');
        this.resultUrl = document.getElementById('resultUrl');
        this.probabilityFill = document.getElementById('probabilityFill');
        this.probabilityValue = document.getElementById('probabilityValue');
        this.historySection = document.getElementById('historySection');
        this.historyList = document.getElementById('historyList');
        this.clearHistoryBtn = document.getElementById('clearHistory');
    }

    attachEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.clearHistoryBtn.addEventListener('click', () => this.clearHistory());
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        const url = this.urlInput.value.trim();
        if (!url) return;

        this.setLoading(true);
        this.hideError();
        this.hideResult();

        try {
            const response = await fetch('http://127.0.0.1:5000/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url })
            });

            if (!response.ok) {
                throw new Error('Backend error');
            }

            const data = await response.json();
            this.displayResult(url, data);
            this.addToHistory(url, data);
            
        } catch (error) {
            console.error('Error:', error);
            this.showError('Error connecting to backend! Make sure the Flask server is running.');
        } finally {
            this.setLoading(false);
            this.urlInput.value = '';
        }
    }

    setLoading(isLoading) {
        this.scanButton.disabled = isLoading;
        this.urlInput.disabled = isLoading;
        
        if (isLoading) {
            this.buttonText.textContent = '⚡ Scanning...';
        } else {
            this.buttonText.textContent = '🔍 Scan URL';
        }
    }

    showError(message) {
        this.errorDiv.textContent = message;
        this.errorDiv.style.display = 'block';
    }

    hideError() {
        this.errorDiv.style.display = 'none';
    }

    displayResult(url, data) {
        const isPhishing = data.prediction === 1;
        const probability = data.probability * 100;

        // Set icon and title
        this.resultIcon.textContent = isPhishing ? '⚠️' : '✅';
        this.resultTitle.textContent = isPhishing ? 'Phishing Detected' : 'Safe URL';
        this.resultUrl.textContent = url;

        // Set probability bar
        this.probabilityFill.style.width = `${probability}%`;
        this.probabilityFill.className = `probability-fill ${isPhishing ? 'danger' : 'safe'}`;
        this.probabilityValue.textContent = `${probability.toFixed(1)}%`;

        // Set result card class
        this.resultDiv.className = `result-card ${isPhishing ? 'phishing' : 'safe'}`;
        
        this.resultDiv.style.display = 'block';
    }

    hideResult() {
        this.resultDiv.style.display = 'none';
    }

    addToHistory(url, data) {
        const timestamp = new Date().toLocaleTimeString();
        const historyItem = {
            url,
            prediction: data.prediction,
            probability: data.probability,
            timestamp
        };

        this.history.unshift(historyItem);
        this.saveHistory();
        this.renderHistory();
    }

    renderHistory() {
        if (this.history.length === 0) {
            this.historySection.style.display = 'none';
            return;
        }

        this.historySection.style.display = 'block';
        this.historyList.innerHTML = '';

        this.history.forEach((item, index) => {
            const historyItem = this.createHistoryItem(item, index);
            this.historyList.appendChild(historyItem);
        });
    }

    createHistoryItem(item, index) {
        const div = document.createElement('div');
        const isPhishing = item.prediction === 1;
        
        div.className = `history-item ${isPhishing ? 'phishing' : 'safe'}`;
        
        div.innerHTML = `
            <div class="history-icon">
                ${isPhishing ? '⚠️' : '✅'}
            </div>
            <div class="history-content">
                <p class="history-url">${item.url}</p>
                <div class="history-meta">
                    <span class="history-status">
                        ${isPhishing ? 'Phishing' : 'Safe'}
                    </span>
                    <span class="history-probability">
                        ${(item.probability * 100).toFixed(1)}% confidence
                    </span>
                    <span class="history-time">${item.timestamp}</span>
                </div>
            </div>
        `;

        return div;
    }

    clearHistory() {
        this.history = [];
        this.saveHistory();
        this.renderHistory();
    }

    saveHistory() {
        localStorage.setItem('phishingDetectorHistory', JSON.stringify(this.history));
    }

    loadHistory() {
        const saved = localStorage.getItem('phishingDetectorHistory');
        return saved ? JSON.parse(saved) : [];
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
});
