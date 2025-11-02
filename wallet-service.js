// wallet-service.js - Secure Web Wallet Service with Persistence
const crypto = require('crypto');
const { scryptSync, randomBytes, createCipheriv, createDecipheriv } = require('crypto');
const fs = require('fs');
const path = require('path');

class WalletPersistence {
    constructor() {
        this.dataDir = './data';
        this.walletsFile = `${this.dataDir}/wallets.json`;
        this.sessionsFile = `${this.dataDir}/sessions.json`;
        this.ensureDataDirectory();
    }

    ensureDataDirectory() {
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }
    }

    saveWallets(wallets) {
        try {
            const serializableWallets = Array.from(wallets.entries()).map(([address, wallet]) => ({
                address,
                encryptedPrivateKey: wallet.encryptedPrivateKey,
                createdAt: wallet.createdAt,
                lastAccess: wallet.lastAccess,
                balance: wallet.balance,
                nonce: wallet.nonce,
                transactionCount: wallet.transactionCount,
                imported: wallet.imported || false
            }));
            fs.writeFileSync(this.walletsFile, JSON.stringify(serializableWallets, null, 2));
            return true;
        } catch (error) {
            console.error('❌ Error saving wallets:', error);
            return false;
        }
    }

    loadWallets() {
        try {
            if (!fs.existsSync(this.walletsFile)) {
                return new Map();
            }
            const data = JSON.parse(fs.readFileSync(this.walletsFile, 'utf8'));
            return new Map(data.map(wallet => [wallet.address, {
                encryptedPrivateKey: wallet.encryptedPrivateKey,
                createdAt: wallet.createdAt,
                lastAccess: wallet.lastAccess,
                balance: wallet.balance || '0',
                nonce: wallet.nonce || 0,
                transactionCount: wallet.transactionCount || 0,
                imported: wallet.imported || false
            }]));
        } catch (error) {
            console.error('❌ Error loading wallets:', error);
            return new Map();
        }
    }

    saveSessions(sessions, loginAttempts) {
        try {
            const serializableSessions = Array.from(sessions.entries()).map(([sessionId, session]) => ({
                sessionId,
                ...session
            }));
            const serializableLoginAttempts = Array.from(loginAttempts.entries()).map(([address, attempts]) => ({
                address,
                ...attempts
            }));
            
            fs.writeFileSync(this.sessionsFile, JSON.stringify({
                sessions: serializableSessions,
                loginAttempts: serializableLoginAttempts
            }, null, 2));
            return true;
        } catch (error) {
            console.error('❌ Error saving sessions:', error);
            return false;
        }
    }

    loadSessions() {
        try {
            if (!fs.existsSync(this.sessionsFile)) {
                return { sessions: new Map(), loginAttempts: new Map() };
            }
            const data = JSON.parse(fs.readFileSync(this.sessionsFile, 'utf8'));
            const sessions = new Map(data.sessions.map(session => [session.sessionId, {
                address: session.address,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt
            }]));
            const loginAttempts = new Map(data.loginAttempts.map(attempt => [attempt.address, {
                count: attempt.count,
                lockUntil: attempt.lockUntil
            }]));
            return { sessions, loginAttempts };
        } catch (error) {
            console.error('❌ Error loading sessions:', error);
            return { sessions: new Map(), loginAttempts: new Map() };
        }
    }
}

class WalletService {
    constructor() {
        this.persistence = new WalletPersistence();
        
        // Load existing data
        const loadedData = this.persistence.loadWallets();
        const loadedSessions = this.persistence.loadSessions();
        
        this.wallets = loadedData;
        this.sessions = loadedSessions.sessions;
        this.loginAttempts = loadedSessions.loginAttempts;
        
        this.MAX_LOGIN_ATTEMPTS = 5;
        this.LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
        
        console.log(`👛 Loaded ${this.wallets.size} wallets and ${this.sessions.size} active sessions`);
    }

    // Save wallet state
    saveState() {
        const walletsSaved = this.persistence.saveWallets(this.wallets);
        const sessionsSaved = this.persistence.saveSessions(this.sessions, this.loginAttempts);
        return walletsSaved && sessionsSaved;
    }

    // Generate a new wallet
    createWallet(password) {
        try {
            // Validate password strength
            if (!this.validatePassword(password)) {
                throw new Error('Password must be at least 8 characters with uppercase, lowercase, number and special character');
            }

            // Generate private key (32 bytes)
            const privateKey = randomBytes(32).toString('hex');
            
            // Generate public address from private key
            const address = this.privateKeyToAddress(privateKey);
            
            // Encrypt private key
            const encryptedPrivateKey = this.encryptPrivateKey(privateKey, password);
            
            const wallet = {
                address: address,
                encryptedPrivateKey: encryptedPrivateKey,
                createdAt: Date.now(),
                lastAccess: Date.now(),
                balance: '0',
                nonce: 0,
                transactionCount: 0
            };

            // Store wallet
            this.wallets.set(address, wallet);
            
            // Save wallet state
            this.saveState();
            console.log(`💾 New wallet created and saved: ${address.substring(0, 10)}...`);

            // Return wallet info (without private key)
            return {
                address: wallet.address,
                createdAt: wallet.createdAt,
                mnemonic: this.generateMnemonic(), // For user backup
                warning: 'Save your private key and mnemonic securely! They cannot be recovered if lost.'
            };
        } catch (error) {
            throw new Error(`Wallet creation failed: ${error.message}`);
        }
    }

    // Import wallet from private key
    importWallet(privateKey, password) {
        try {
            // Validate private key format
            if (!this.validatePrivateKey(privateKey)) {
                throw new Error('Invalid private key format');
            }

            // Generate address from private key
            const address = this.privateKeyToAddress(privateKey);
            
            // Check if wallet already exists
            if (this.wallets.has(address)) {
                throw new Error('Wallet already exists');
            }

            // Encrypt private key
            const encryptedPrivateKey = this.encryptPrivateKey(privateKey, password);
            
            const wallet = {
                address: address,
                encryptedPrivateKey: encryptedPrivateKey,
                createdAt: Date.now(),
                lastAccess: Date.now(),
                balance: '0',
                nonce: 0,
                transactionCount: 0,
                imported: true
            };

            this.wallets.set(address, wallet);
            
            // Save wallet state
            this.saveState();
            console.log(`💾 Wallet imported and saved: ${address.substring(0, 10)}...`);

            return {
                address: wallet.address,
                imported: true,
                createdAt: wallet.createdAt
            };
        } catch (error) {
            throw new Error(`Wallet import failed: ${error.message}`);
        }
    }

    // Login to wallet
    loginWallet(address, password) {
        try {
            // Check login attempts
            const attempts = this.loginAttempts.get(address) || { count: 0, lockUntil: 0 };
            if (Date.now() < attempts.lockUntil) {
                const remainingTime = Math.ceil((attempts.lockUntil - Date.now()) / 60000);
                throw new Error(`Too many failed attempts. Try again in ${remainingTime} minutes`);
            }

            const wallet = this.wallets.get(address);
            if (!wallet) {
                this.recordFailedAttempt(address);
                throw new Error('Wallet not found');
            }

            // Decrypt private key to verify password
            const privateKey = this.decryptPrivateKey(wallet.encryptedPrivateKey, password);
            
            // Verify the private key generates the correct address
            const derivedAddress = this.privateKeyToAddress(privateKey);
            if (derivedAddress !== address) {
                this.recordFailedAttempt(address);
                throw new Error('Invalid password');
            }

            // Reset login attempts on successful login
            this.loginAttempts.delete(address);
            
            // Update last access
            wallet.lastAccess = Date.now();
            this.wallets.set(address, wallet);

            // Create session
            const sessionId = this.createSession(address);
            
            // Save wallet state
            this.saveState();
            console.log(`💾 Wallet login recorded: ${address.substring(0, 10)}...`);

            return {
                sessionId: sessionId,
                address: wallet.address,
                balance: wallet.balance,
                nonce: wallet.nonce
            };
        } catch (error) {
            this.recordFailedAttempt(address);
            throw new Error(`Login failed: ${error.message}`);
        }
    }

    // Get wallet balance and info
    getWalletInfo(address, sessionId) {
        if (!this.verifySession(address, sessionId)) {
            throw new Error('Invalid session');
        }

        const wallet = this.wallets.get(address);
        if (!wallet) {
            throw new Error('Wallet not found');
        }

        return {
            address: wallet.address,
            balance: wallet.balance,
            nonce: wallet.nonce,
            transactionCount: wallet.transactionCount,
            createdAt: wallet.createdAt,
            lastAccess: wallet.lastAccess
        };
    }

    // Sign transaction
    signTransaction(transactionData, address, sessionId) {
        if (!this.verifySession(address, sessionId)) {
            throw new Error('Invalid session');
        }

        const wallet = this.wallets.get(address);
        if (!wallet) {
            throw new Error('Wallet not found');
        }

        // In a real implementation, you would decrypt the private key and sign the transaction
        // For security, this should be done on the client side in a real application
        const transactionHash = this.calculateTransactionHash(transactionData);
        
        // Simulate signing (in production, use proper ECDSA signing)
        const signature = {
            v: 27,
            r: '0x' + randomBytes(32).toString('hex'),
            s: '0x' + randomBytes(32).toString('hex')
        };

        return {
            ...transactionData,
            hash: transactionHash,
            from: address,
            signature: signature
        };
    }

    // Logout
    logoutWallet(address, sessionId) {
        this.sessions.delete(sessionId);
        
        // Save session state
        this.saveState();
        console.log(`💾 Wallet logout recorded: ${address.substring(0, 10)}...`);

        return { success: true, message: 'Logged out successfully' };
    }

    // Helper methods
    validatePassword(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        
        return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
    }

    validatePrivateKey(privateKey) {
        return /^[a-fA-F0-9]{64}$/.test(privateKey);
    }

    privateKeyToAddress(privateKey) {
        // In real implementation, use proper ECDSA to derive address
        // This is a simplified version for demo
        const hash = crypto.createHash('sha256').update(privateKey).digest('hex');
        return '0x' + hash.substring(0, 40);
    }

    encryptPrivateKey(privateKey, password) {
        const salt = randomBytes(16);
        const key = scryptSync(password, salt, 32);
        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-gcm', key, iv);
        
        let encrypted = cipher.update(privateKey, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return {
            encryptedData: encrypted,
            iv: iv.toString('hex'),
            salt: salt.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    decryptPrivateKey(encryptedData, password) {
        try {
            const key = scryptSync(password, Buffer.from(encryptedData.salt, 'hex'), 32);
            const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'hex'));
            decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
            
            let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            throw new Error('Decryption failed - wrong password');
        }
    }

    generateMnemonic() {
        // In real implementation, use BIP39
        const words = [
            'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
            'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid'
        ];
        return Array.from({ length: 12 }, () => words[Math.floor(Math.random() * words.length)]).join(' ');
    }

    createSession(address) {
        const sessionId = randomBytes(32).toString('hex');
        this.sessions.set(sessionId, {
            address: address,
            createdAt: Date.now(),
            expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
        });
        
        // Save session state
        this.saveState();
        
        return sessionId;
    }

    verifySession(address, sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        if (session.expiresAt < Date.now()) {
            this.sessions.delete(sessionId);
            return false;
        }
        return session.address === address;
    }

    recordFailedAttempt(address) {
        const attempts = this.loginAttempts.get(address) || { count: 0, lockUntil: 0 };
        attempts.count++;
        
        if (attempts.count >= this.MAX_LOGIN_ATTEMPTS) {
            attempts.lockUntil = Date.now() + this.LOCKOUT_TIME;
            attempts.count = 0;
        }
        
        this.loginAttempts.set(address, attempts);
        
        // Save login attempts state
        this.saveState();
    }

    calculateTransactionHash(transaction) {
        return '0x' + crypto.createHash('sha256').update(JSON.stringify(transaction)).digest('hex');
    }

    // Clean up expired sessions
    cleanupSessions() {
        const now = Date.now();
        let cleaned = false;
        for (const [sessionId, session] of this.sessions.entries()) {
            if (session.expiresAt < now) {
                this.sessions.delete(sessionId);
                cleaned = true;
            }
        }
        
        if (cleaned) {
            this.saveState();
        }
    }
}

module.exports = WalletService;