// wallet.js - Tesam Secure Wallet (Fixed Balance Handling)
class TesamWallet {
    constructor() {
        this.currentWallet = null;
        this.privateKey = null;
        this.apiBase = window.location.origin;
        this.currentTheme = 'light';
        this.init();
    }

    init() {
        this.loadTheme();
        this.bindEvents();
        this.checkExistingWallet();
    }

    loadTheme() {
        const savedTheme = localStorage.getItem('tesam_theme') || 'light';
        this.setTheme(savedTheme);
    }

    setTheme(theme) {
        this.currentTheme = theme;
        document.body.setAttribute('data-theme', theme);
        localStorage.setItem('tesam_theme', theme);
        
        const themeIcon = document.querySelector('.theme-toggle i');
        themeIcon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }

    toggleTheme() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.setTheme(newTheme);
    }

    bindEvents() {
        // Setup options
        document.getElementById('createOption').addEventListener('click', () => this.showCreateForm());
        document.getElementById('importOption').addEventListener('click', () => this.showImportForm());
        
        // Wallet actions
        document.getElementById('createWalletBtn').addEventListener('click', () => this.createWallet());
        document.getElementById('importWalletBtn').addEventListener('click', () => this.importWallet());
        document.getElementById('refreshBalanceBtn').addEventListener('click', () => this.loadWalletInfo());
        document.getElementById('disconnectBtn').addEventListener('click', () => this.disconnectWallet());
        document.getElementById('exportWalletBtn').addEventListener('click', () => this.exportWallet());
        
        // Private key management
        document.getElementById('showPrivateKeyBtn').addEventListener('click', () => this.showPrivateKey());
        document.getElementById('hidePrivateKeyBtn').addEventListener('click', () => this.hidePrivateKey());
        document.getElementById('copyAddressBtn').addEventListener('click', () => this.copyToClipboard('walletAddress'));
        document.getElementById('copyPrivateKeyBtn').addEventListener('click', () => this.copyToClipboard('privateKeyDisplay'));
        
        // Transaction form
        document.getElementById('sendTransactionForm').addEventListener('submit', (e) => this.sendTransaction(e));
        
        // Amount calculation
        document.getElementById('sendAmount').addEventListener('input', () => this.calculateFee());
        document.getElementById('gasLimit').addEventListener('input', () => this.calculateFee());

        // Global theme toggle
        window.toggleTheme = () => this.toggleTheme();
    }

    showCreateForm() {
        document.getElementById('createOption').classList.add('active');
        document.getElementById('importOption').classList.remove('active');
        document.getElementById('createForm').classList.remove('hidden');
        document.getElementById('importForm').classList.add('hidden');
    }

    showImportForm() {
        document.getElementById('importOption').classList.add('active');
        document.getElementById('createOption').classList.remove('active');
        document.getElementById('importForm').classList.remove('hidden');
        document.getElementById('createForm').classList.add('hidden');
    }

    async createWallet() {
        try {
            const btn = document.getElementById('createWalletBtn');
            btn.disabled = true;
            btn.innerHTML = '<span class="loading-spinner"></span> Generating Secure Wallet...';

            const response = await fetch(`${this.apiBase}/wallet/create`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            const data = await response.json();

            if (data.success) {
                this.currentWallet = data.data.address;
                this.privateKey = data.data.privateKey;
                
                // Store wallet securely in session storage
                sessionStorage.setItem('tesam_wallet', JSON.stringify({
                    address: this.currentWallet,
                    privateKey: this.privateKey,
                    timestamp: Date.now()
                }));

                this.showDashboard();
                this.showPrivateKey(); // Show private key once for user to save
                this.showNotification('🎉 Wallet created successfully! Save your private key securely.', 'success');
            } else {
                throw new Error(data.error || 'Failed to create wallet');
            }
        } catch (error) {
            console.error('Wallet creation error:', error);
            this.showNotification('❌ Failed to create wallet: ' + error.message, 'error');
        } finally {
            const btn = document.getElementById('createWalletBtn');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-plus"></i> Generate Secure Wallet';
        }
    }

    async importWallet() {
        let privateKey = document.getElementById('privateKey').value.trim();
        
        if (!privateKey) {
            this.showNotification('❌ Please enter your private key', 'error');
            return;
        }

        // Remove 0x prefix if present
        if (privateKey.startsWith('0x')) {
            privateKey = privateKey.substring(2);
        }

        // Validate private key format
        if (!/^[a-fA-F0-9]{64}$/.test(privateKey)) {
            this.showNotification('❌ Invalid private key format. Must be 64 hexadecimal characters.', 'error');
            return;
        }

        try {
            const btn = document.getElementById('importWalletBtn');
            btn.disabled = true;
            btn.innerHTML = '<span class="loading-spinner"></span> Importing Wallet...';

            const response = await fetch(`${this.apiBase}/wallet/import`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ privateKey: '0x' + privateKey })
            });

            const data = await response.json();

            if (data.success) {
                this.currentWallet = data.data.address;
                this.privateKey = data.data.privateKey;
                
                // Store wallet securely in session storage
                sessionStorage.setItem('tesam_wallet', JSON.stringify({
                    address: this.currentWallet,
                    privateKey: this.privateKey,
                    timestamp: Date.now()
                }));

                this.showDashboard();
                this.showNotification('✅ Wallet imported successfully!', 'success');
            } else {
                throw new Error(data.error || 'Invalid private key');
            }
        } catch (error) {
            console.error('Wallet import error:', error);
            this.showNotification('❌ Failed to import wallet: ' + error.message, 'error');
        } finally {
            const btn = document.getElementById('importWalletBtn');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-download"></i> Import Wallet';
        }
    }

    checkExistingWallet() {
        const stored = sessionStorage.getItem('tesam_wallet');
        if (stored) {
            try {
                const wallet = JSON.parse(stored);
                // Check if session is not too old (max 24 hours)
                if (Date.now() - wallet.timestamp < 24 * 60 * 60 * 1000) {
                    this.currentWallet = wallet.address;
                    this.privateKey = wallet.privateKey;
                    this.showDashboard();
                    this.showNotification('🔓 Wallet loaded from session', 'info');
                } else {
                    sessionStorage.removeItem('tesam_wallet');
                    this.showNotification('🔒 Session expired. Please reconnect your wallet.', 'warning');
                }
            } catch (error) {
                console.error('Error loading stored wallet:', error);
                sessionStorage.removeItem('tesam_wallet');
            }
        }
    }

    showDashboard() {
        document.getElementById('walletSetup').style.display = 'none';
        document.getElementById('walletDashboard').style.display = 'block';
        this.loadWalletInfo();
        this.calculateFee();
    }

    async loadWalletInfo() {
        if (!this.currentWallet || !this.privateKey) return;

        try {
            const btn = document.getElementById('refreshBalanceBtn');
            btn.classList.add('loading');
            btn.innerHTML = '<span class="loading-spinner"></span> Refreshing...';

            const response = await fetch(`${this.apiBase}/wallet/info`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ privateKey: this.privateKey })
            });

            const data = await response.json();

            if (data.success) {
                this.updateWalletDisplay(data.data);
                this.loadTransactionHistory(data.data.recentTransactions);
                this.showNotification('✅ Balance updated', 'success');
            } else {
                throw new Error(data.error || 'Failed to load wallet info');
            }
        } catch (error) {
            console.error('Wallet info error:', error);
            this.showNotification('❌ Failed to load wallet information', 'error');
        } finally {
            const btn = document.getElementById('refreshBalanceBtn');
            btn.classList.remove('loading');
            btn.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
        }
    }

    updateWalletDisplay(walletData) {
        // Update balance - walletData.balance.tesam should be the actual TESAM amount
        const balance = parseFloat(walletData.balance.tesam);
        document.getElementById('balanceAmount').textContent = 
            `${this.formatNumber(balance)} TESAM`;
        
        // Update available balance
        document.getElementById('availableBalance').textContent = this.formatNumber(balance);
        
        // Update address
        document.getElementById('walletAddress').textContent = walletData.address;
        
        // Update private key display if shown
        const privateKeyDisplay = document.getElementById('privateKeyDisplay');
        if (!privateKeyDisplay.classList.contains('hidden')) {
            privateKeyDisplay.textContent = this.privateKey;
        }

        // Update USD value if available
        this.updateUSDValue(balance);
    }

    formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(2) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(2) + 'K';
        } else {
            return num.toFixed(6);
        }
    }

    async updateUSDValue(balanceTESAM) {
        try {
            const response = await fetch(`${this.apiBase}/market`);
            if (response.ok) {
                const marketData = await response.json();
                const usdValue = balanceTESAM * parseFloat(marketData.price);
                document.getElementById('balanceUSD').textContent = `$${this.formatNumber(usdValue)} USD`;
            }
        } catch (error) {
            document.getElementById('balanceUSD').textContent = '-';
        }
    }

    loadTransactionHistory(transactions) {
        const container = document.getElementById('transactionList');
        const noTransactions = document.getElementById('noTransactions');
        
        if (!transactions || transactions.length === 0) {
            noTransactions.style.display = 'block';
            container.innerHTML = '';
            container.appendChild(noTransactions);
            return;
        }
        
        noTransactions.style.display = 'none';
        
        const transactionsHtml = transactions.map(tx => {
            // FIXED: Parse amount properly - it should already be in TESAM from the API
            const amount = parseFloat(tx.amount);
            const isOutgoing = tx.from.toLowerCase() === this.currentWallet.toLowerCase();
            const counterparty = isOutgoing ? tx.to : tx.from;
            
            return `
                <div class="transaction-item">
                    <div class="tx-header">
                        <span class="tx-hash" title="${tx.hash}">${tx.hash.substring(0, 16)}...</span>
                        <span class="tx-amount ${isOutgoing ? 'text-error' : 'text-success'}">
                            ${isOutgoing ? '-' : '+'}${this.formatNumber(amount)} TESAM
                        </span>
                    </div>
                    <div class="tx-details">
                        <div><strong>${isOutgoing ? 'To:' : 'From:'}</strong> 
                            <span class="tx-${isOutgoing ? 'to' : 'from'}" title="${counterparty}">
                                ${counterparty.substring(0, 16)}...
                            </span>
                        </div>
                        <div><strong>Block:</strong> ${tx.blockNumber || 'Pending'}</div>
                        <div><strong>Gas:</strong> ${(tx.gas || 0).toLocaleString()}</div>
                        <div><strong>Status:</strong> 
                            <span class="tx-status ${tx.status === 'success' ? 'confirmed' : 'pending'}">
                                <i class="fas ${tx.status === 'success' ? 'fa-check-circle' : 'fa-clock'}"></i>
                                ${tx.status === 'success' ? 'Confirmed' : 'Pending'}
                            </span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
        container.innerHTML = transactionsHtml;
    }

    calculateFee() {
        const gasLimit = parseInt(document.getElementById('gasLimit').value) || 21000;
        const gasPrice = 20; // 20 Gwei
        const fee = (gasLimit * gasPrice) / 1e9;
        document.getElementById('transactionFee').textContent = `${fee.toFixed(8)} TESAM`;
    }

    // FIXED: Proper BigInt conversion for large numbers
    convertToWei(amount) {
        // Convert the amount to a string to avoid scientific notation
        const amountStr = amount.toString();
        
        // Check if it's a decimal number
        if (amountStr.includes('.')) {
            const [integerPart, decimalPart] = amountStr.split('.');
            // Pad the decimal part to 18 decimal places
            const paddedDecimal = decimalPart.padEnd(18, '0').substring(0, 18);
            return BigInt(integerPart + paddedDecimal);
        } else {
            // If it's a whole number, just multiply by 1e18
            return BigInt(amountStr) * BigInt('1000000000000000000');
        }
    }

    async sendTransaction(e) {
        e.preventDefault();
        
        if (!this.currentWallet || !this.privateKey) {
            this.showNotification('❌ Wallet not connected', 'error');
            return;
        }

        const to = document.getElementById('recipientAddress').value.trim();
        const amount = parseFloat(document.getElementById('sendAmount').value);
        const gas = parseInt(document.getElementById('gasLimit').value);

        if (!to || !amount || amount <= 0) {
            this.showNotification('❌ Please fill all fields correctly', 'error');
            return;
        }

        // Validate address format
        if (!/^0x[a-fA-F0-9]{40}$/.test(to)) {
            this.showNotification('❌ Invalid recipient address format', 'error');
            return;
        }

        try {
            const btn = e.target.querySelector('button[type="submit"]');
            btn.disabled = true;
            btn.classList.add('loading');
            btn.innerHTML = '<span class="loading-spinner"></span> Sending Transaction...';

            // FIXED: Use proper BigInt conversion
            const amountWei = this.convertToWei(amount).toString();

            console.log('Sending transaction:', {
                from: this.currentWallet,
                to: to,
                amount: amountWei,
                amountTESAM: amount,
                gas: gas
            });

            const response = await fetch(`${this.apiBase}/transaction/send`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                    from: this.currentWallet,
                    to: to,
                    amount: amountWei,
                    gas: gas,
                    privateKey: this.privateKey
                })
            });

            const data = await response.json();

            if (data.success) {
                this.showNotification('✅ Transaction sent successfully!', 'success');
                document.getElementById('sendTransactionForm').reset();
                
                // Refresh balance and transactions after a delay
                setTimeout(() => {
                    this.loadWalletInfo();
                }, 3000);
            } else {
                throw new Error(data.error || 'Transaction failed');
            }
        } catch (error) {
            console.error('Send transaction error:', error);
            this.showNotification('❌ Transaction failed: ' + error.message, 'error');
        } finally {
            const btn = e.target.querySelector('button[type="submit"]');
            btn.disabled = false;
            btn.classList.remove('loading');
            btn.innerHTML = '<i class="fas fa-paper-plane"></i> Send Transaction';
        }
    }

    showPrivateKey() {
        if (!this.privateKey) return;
        
        document.getElementById('privateKeyDisplay').textContent = this.privateKey;
        document.getElementById('privateKeySection').classList.remove('hidden');
        document.getElementById('showPrivateKeyBtn').style.display = 'none';
        
        this.showNotification('⚠️ Private key revealed. Save it securely!', 'warning');
    }

    hidePrivateKey() {
        document.getElementById('privateKeyDisplay').textContent = '-';
        document.getElementById('privateKeySection').classList.add('hidden');
        document.getElementById('showPrivateKeyBtn').style.display = 'block';
    }

    exportWallet() {
        if (!this.currentWallet || !this.privateKey) return;
        
        const walletData = {
            address: this.currentWallet,
            privateKey: this.privateKey,
            network: "Tesam Blockchain",
            warning: "KEEP THIS INFORMATION SECURE! Never share your private key with anyone.",
            exportDate: new Date().toISOString(),
            securityNotice: "This file contains sensitive information. Store it in a secure location."
        };
        
        const blob = new Blob([JSON.stringify(walletData, null, 2)], { 
            type: 'application/json' 
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `tesam-wallet-backup-${this.currentWallet.substring(2, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showNotification('💾 Wallet backup exported successfully', 'success');
    }

    disconnectWallet() {
        if (confirm('Are you sure you want to disconnect your wallet? You will need your private key to reconnect.')) {
            this.currentWallet = null;
            this.privateKey = null;
            sessionStorage.removeItem('tesam_wallet');
            
            document.getElementById('walletDashboard').style.display = 'none';
            document.getElementById('walletSetup').style.display = 'block';
            document.getElementById('importForm').classList.add('hidden');
            document.getElementById('createForm').classList.remove('hidden');
            document.getElementById('privateKey').value = '';
            
            this.showNotification('🔌 Wallet disconnected', 'info');
        }
    }

    copyToClipboard(elementId) {
        const element = document.getElementById(elementId);
        const text = element.textContent;
        
        navigator.clipboard.writeText(text).then(() => {
            this.showNotification('📋 Copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Copy failed:', err);
            this.showNotification('❌ Copy failed', 'error');
        });
    }

    showNotification(message, type = 'info') {
        // Remove existing notifications
        const existing = document.querySelector('.wallet-notification');
        if (existing) existing.remove();

        // Create notification
        const notification = document.createElement('div');
        notification.className = `wallet-notification ${type}`;
        
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };

        notification.innerHTML = `
            <i class="${icons[type] || icons.info}"></i>
            <span>${message}</span>
        `;

        notification.style.cssText = `
            position: fixed;
            top: 100px;
            right: 20px;
            padding: 16px 20px;
            border-radius: 12px;
            color: white;
            font-weight: 500;
            z-index: 10000;
            max-width: 400px;
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 10px;
            animation: slideInRight 0.3s ease;
            border-left: 4px solid ${this.getNotificationColor(type)};
        `;

        // Set background color based on type
        notification.style.background = this.getNotificationColor(type);

        document.body.appendChild(notification);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'slideOutRight 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }
        }, 5000);
    }

    getNotificationColor(type) {
        const colors = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b',
            info: '#3b82f6'
        };
        return colors[type] || colors.info;
    }
}

// Initialize wallet when page loads
document.addEventListener('DOMContentLoaded', () => {
    new TesamWallet();
});

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOutRight {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    
    .wallet-notification {
        font-family: 'Inter', sans-serif;
    }
`;
document.head.appendChild(style);