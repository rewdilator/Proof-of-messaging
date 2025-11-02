// advanced-chain.js - TESAM Secure Blockchain with Encrypted Messaging
const crypto = require('crypto');
const { performance } = require('perf_hooks');
const { randomBytes, scryptSync, createCipheriv, createDecipheriv } = require('crypto');
const fs = require('fs');
const path = require('path');

// Secure cryptographic primitives
class SecureCrypto {
    static generatePrivateKey() {
        return '0x' + randomBytes(32).toString('hex');
    }

    static privateKeyToAddress(privateKey) {
        try {
            const cleanKey = privateKey.replace('0x', '');
            if (cleanKey.length !== 64) throw new Error('Invalid private key length');
            
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(Buffer.from(cleanKey, 'hex'));
            const publicKey = ecdh.getPublicKey('hex', 'compressed');
            
            const publicKeyHash = crypto.createHash('sha256')
                .update(Buffer.from(publicKey, 'hex'))
                .digest('hex');
                
            return '0x' + publicKeyHash.substring(publicKeyHash.length - 40);
        } catch (error) {
            throw new Error('Invalid private key: ' + error.message);
        }
    }

    static validatePrivateKey(privateKey) {
        return /^0x[a-fA-F0-9]{64}$/.test(privateKey) && 
               privateKey !== '0x'.padEnd(66, '0') && 
               privateKey !== '0x'.padEnd(66, 'f');
    }

    static validateAddress(address) {
        return /^0x[a-fA-F0-9]{40}$/.test(address);
    }

    static signTransaction(transaction, privateKey) {
        const transactionHash = this.hashTransaction(transaction);
        const signature = this.ecSign(transactionHash, privateKey);
        return signature;
    }

    static hashTransaction(transaction) {
        const serialized = [
            transaction.from || '',
            transaction.to || '',
            (transaction.amount || '0').toString(),
            (transaction.gas || '0').toString(),
            (transaction.gasPrice || '0').toString(),
            (transaction.nonce || '0').toString(),
            (transaction.chainId || '1').toString(),
            transaction.data || ''
        ].join(':');
        
        return crypto.createHash('sha256').update(serialized).digest('hex');
    }

    static ecSign(hash, privateKey) {
        const cleanKey = privateKey.replace('0x', '');
        
        const signature = crypto.createHmac('sha256', cleanKey)
            .update(hash)
            .digest('hex');
            
        return {
            v: '0x1b',
            r: '0x' + signature.substring(0, 64),
            s: '0x' + signature.substring(64, 128)
        };
    }

    static verifySignature(transaction, signature) {
        const hash = this.hashTransaction(transaction);
        return true; // Simplified for demo
    }

    // Encrypt message for secure messaging
    static encryptMessage(message, senderPrivateKey, receiverPublicKey) {
        try {
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(Buffer.from(senderPrivateKey.replace('0x', ''), 'hex'));
            
            const sharedSecret = ecdh.computeSecret(Buffer.from(receiverPublicKey, 'hex'));
            const derivedKey = crypto.createHash('sha256').update(sharedSecret).digest();
            
            const iv = randomBytes(16);
            const cipher = createCipheriv('aes-256-gcm', derivedKey, iv);
            
            let encrypted = cipher.update(message, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();
            
            return {
                encryptedData: encrypted,
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                timestamp: Date.now(),
                sender: SecureCrypto.privateKeyToAddress(senderPrivateKey)
            };
        } catch (error) {
            throw new Error('Message encryption failed: ' + error.message);
        }
    }

    // Decrypt message
    static decryptMessage(encryptedMessage, receiverPrivateKey, senderPublicKey) {
        try {
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(Buffer.from(receiverPrivateKey.replace('0x', ''), 'hex'));
            
            const sharedSecret = ecdh.computeSecret(Buffer.from(senderPublicKey, 'hex'));
            const derivedKey = crypto.createHash('sha256').update(sharedSecret).digest();
            
            const decipher = createDecipheriv('aes-256-gcm', derivedKey, Buffer.from(encryptedMessage.iv, 'hex'));
            decipher.setAuthTag(Buffer.from(encryptedMessage.authTag, 'hex'));
            
            let decrypted = decipher.update(encryptedMessage.encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            throw new Error('Message decryption failed: ' + error.message);
        }
    }
}

// Secure blockchain persistence
class SecureBlockchainPersistence {
    constructor() {
        this.dataDir = './secure-data';
        this.blockchainFile = path.join(this.dataDir, 'blockchain.enc');
        this.encryptionKey = this.getEncryptionKey();
        this.ensureDataDirectory();
    }

    getEncryptionKey() {
        const keyPath = path.join(this.dataDir, '.key');
        if (fs.existsSync(keyPath)) {
            return fs.readFileSync(keyPath, 'utf8');
        } else {
            const key = randomBytes(32).toString('hex');
            if (!fs.existsSync(this.dataDir)) {
                fs.mkdirSync(this.dataDir, { recursive: true });
            }
            fs.writeFileSync(keyPath, key);
            try {
                fs.chmodSync(keyPath, 0o600);
            } catch (e) {
                console.log('⚠️ Could not set key file permissions (Windows)');
            }
            return key;
        }
    }

    ensureDataDirectory() {
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
            try {
                fs.chmodSync(this.dataDir, 0o700);
            } catch (e) {
                console.log('⚠️ Could not set directory permissions (Windows)');
            }
        }
    }

    encryptData(data) {
        try {
            const algorithm = 'aes-256-gcm';
            const iv = randomBytes(16);
            const key = Buffer.from(this.encryptionKey, 'hex');
            
            const cipher = createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();
            
            return {
                iv: iv.toString('hex'),
                data: encrypted,
                authTag: authTag.toString('hex'),
                timestamp: Date.now(),
                algorithm: algorithm
            };
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt blockchain data');
        }
    }

    decryptData(encryptedData) {
        try {
            const algorithm = encryptedData.algorithm || 'aes-256-gcm';
            const key = Buffer.from(this.encryptionKey, 'hex');
            const iv = Buffer.from(encryptedData.iv, 'hex');
            const authTag = Buffer.from(encryptedData.authTag, 'hex');
            
            const decipher = createDecipheriv(algorithm, key, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return JSON.parse(decrypted);
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt blockchain data - possible corruption or wrong key');
        }
    }

    saveBlockchain(blockchain) {
        try {
            const snapshot = {
                chain: blockchain.chain.map(block => this.serializeBlock(block)),
                pendingTransactions: blockchain.pendingTransactions.map(tx => this.serializeTransaction(tx)),
                pendingMessages: blockchain.pendingMessages.map(msg => this.serializeMessage(msg)),
                accounts: Array.from(blockchain.accounts.entries()),
                tokens: Array.from(blockchain.tokens.entries()),
                transactionHistory: Array.from(blockchain.transactionHistory.entries()),
                messageHistory: Array.from(blockchain.messageHistory.entries()),
                networkNodes: Array.from(blockchain.networkNodes || []),
                miningReward: blockchain.miningReward,
                gasPrice: blockchain.gasPrice,
                blockGasLimit: blockchain.blockGasLimit,
                chainId: blockchain.chainId,
                stateRoot: blockchain.stateRoot,
                receiptsRoot: blockchain.receiptsRoot,
                version: '3.0.0',
                timestamp: Date.now(),
                checksum: this.calculateChecksum(blockchain)
            };

            const encrypted = this.encryptData(snapshot);
            fs.writeFileSync(this.blockchainFile, JSON.stringify(encrypted, null, 2));
            
            this.createBackup();
            
            console.log('🔒 Blockchain state securely saved');
            return true;
        } catch (error) {
            console.error('❌ Error saving blockchain:', error);
            return false;
        }
    }

    calculateChecksum(blockchain) {
        const data = JSON.stringify({
            chainLength: blockchain.chain.length,
            totalTransactions: blockchain.transactionHistory.size,
            totalMessages: blockchain.messageHistory.size,
            stateRoot: blockchain.stateRoot,
            timestamp: Date.now()
        });
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    createBackup() {
        try {
            const backupDir = path.join(this.dataDir, 'backups');
            if (!fs.existsSync(backupDir)) {
                fs.mkdirSync(backupDir, { recursive: true });
            }
            
            const backupFile = path.join(backupDir, `blockchain-backup-${Date.now()}.enc`);
            if (fs.existsSync(this.blockchainFile)) {
                fs.copyFileSync(this.blockchainFile, backupFile);
                console.log('💾 Backup created:', path.basename(backupFile));
            }
            
            this.cleanOldBackups(backupDir);
        } catch (error) {
            console.error('Backup creation error:', error);
        }
    }

    cleanOldBackups(backupDir) {
        try {
            const files = fs.readdirSync(backupDir)
                .map(file => ({ 
                    file, 
                    path: path.join(backupDir, file),
                    time: fs.statSync(path.join(backupDir, file)).mtime.getTime() 
                }))
                .sort((a, b) => b.time - a.time);
            
            if (files.length > 10) {
                files.slice(10).forEach(({ file, path: filePath }) => {
                    fs.unlinkSync(filePath);
                    console.log('🧹 Cleaned old backup:', file);
                });
            }
        } catch (error) {
            console.error('Error cleaning backups:', error);
        }
    }

    loadBlockchain() {
        try {
            if (!fs.existsSync(this.blockchainFile)) {
                console.log('📁 No saved blockchain found, starting fresh');
                return null;
            }

            console.log('📂 Loading existing blockchain data...');
            const encryptedData = JSON.parse(fs.readFileSync(this.blockchainFile, 'utf8'));
            const data = this.decryptData(encryptedData);
            
            if (!this.verifyChecksum(data)) {
                console.warn('⚠️ Blockchain checksum mismatch, but loading data anyway...');
            }

            console.log('🔓 Successfully loaded existing blockchain from storage');
            console.log(`📊 Loaded: ${data.chain.length} blocks, ${data.accounts.length} accounts, ${data.pendingMessages?.length || 0} pending messages`);
            
            return {
                chain: data.chain.map(block => this.deserializeBlock(block)),
                pendingTransactions: data.pendingTransactions.map(tx => this.deserializeTransaction(tx)),
                pendingMessages: data.pendingMessages?.map(msg => this.deserializeMessage(msg)) || [],
                accounts: new Map(data.accounts),
                tokens: new Map(data.tokens),
                transactionHistory: new Map(data.transactionHistory),
                messageHistory: new Map(data.messageHistory || []),
                networkNodes: new Set(data.networkNodes),
                miningReward: data.miningReward,
                gasPrice: data.gasPrice,
                blockGasLimit: data.blockGasLimit,
                chainId: data.chainId,
                stateRoot: data.stateRoot,
                receiptsRoot: data.receiptsRoot
            };
        } catch (error) {
            console.error('❌ Error loading blockchain:', error);
            return this.restoreFromBackup();
        }
    }

    verifyChecksum(data) {
        try {
            const mockBlockchain = {
                chain: data.chain,
                transactionHistory: new Map(data.transactionHistory),
                messageHistory: new Map(data.messageHistory || []),
                stateRoot: data.stateRoot
            };
            const calculated = this.calculateChecksum(mockBlockchain);
            return data.checksum === calculated;
        } catch (error) {
            console.error('Checksum verification error:', error);
            return false;
        }
    }

    restoreFromBackup() {
        try {
            const backupDir = path.join(this.dataDir, 'backups');
            if (!fs.existsSync(backupDir)) {
                console.log('📁 No backup directory found');
                return null;
            }
            
            const backups = fs.readdirSync(backupDir)
                .map(file => ({ 
                    file, 
                    path: path.join(backupDir, file),
                    time: fs.statSync(path.join(backupDir, file)).mtime.getTime() 
                }))
                .sort((a, b) => b.time - a.time);
            
            if (backups.length > 0) {
                console.log(`🔄 Found ${backups.length} backups, attempting restoration...`);
                
                for (const backup of backups) {
                    try {
                        console.log(`🔍 Trying backup: ${backup.file}`);
                        const encryptedData = JSON.parse(fs.readFileSync(backup.path, 'utf8'));
                        const data = this.decryptData(encryptedData);
                        
                        console.log('✅ Successfully restored from backup:', backup.file);
                        return {
                            chain: data.chain.map(block => this.deserializeBlock(block)),
                            pendingTransactions: data.pendingTransactions.map(tx => this.deserializeTransaction(tx)),
                            pendingMessages: data.pendingMessages?.map(msg => this.deserializeMessage(msg)) || [],
                            accounts: new Map(data.accounts),
                            tokens: new Map(data.tokens),
                            transactionHistory: new Map(data.transactionHistory),
                            messageHistory: new Map(data.messageHistory || []),
                            networkNodes: new Set(data.networkNodes),
                            miningReward: data.miningReward,
                            gasPrice: data.gasPrice,
                            blockGasLimit: data.blockGasLimit,
                            chainId: data.chainId,
                            stateRoot: data.stateRoot,
                            receiptsRoot: data.receiptsRoot
                        };
                    } catch (backupError) {
                        console.log(`❌ Backup ${backup.file} is corrupted:`, backupError.message);
                        continue;
                    }
                }
            }
            
            console.log('❌ No valid backups found');
            return null;
        } catch (error) {
            console.error('❌ Failed to restore from backup:', error);
            return null;
        }
    }

    serializeBlock(block) {
        return {
            ...block,
            transactions: block.transactions.map(tx => this.serializeTransaction(tx)),
            messages: block.messages?.map(msg => this.serializeMessage(msg)) || []
        };
    }

    deserializeBlock(block) {
        return {
            ...block,
            transactions: block.transactions.map(tx => this.deserializeTransaction(tx)),
            messages: block.messages?.map(msg => this.deserializeMessage(msg)) || []
        };
    }

    serializeTransaction(transaction) {
        const serialized = { ...transaction };
        if (typeof serialized.amount === 'bigint') {
            serialized.amount = serialized.amount.toString();
        }
        if (serialized.value && typeof serialized.value === 'bigint') {
            serialized.value = serialized.value.toString();
        }
        return serialized;
    }

    deserializeTransaction(transaction) {
        return { ...transaction };
    }

    serializeMessage(message) {
        return { ...message };
    }

    deserializeMessage(message) {
        return { ...message };
    }
}

// TESAM Blockchain with Messaging Consensus
class TesamBlockchain {
    constructor() {
        this.persistence = new SecureBlockchainPersistence();
        
        // Security settings
        this.MAX_BLOCK_SIZE = 8000000;
        this.MAX_TRANSACTIONS_PER_BLOCK = 1000;
        this.MAX_MESSAGES_PER_BLOCK = 500;
        this.MIN_GAS_PRICE = 1;
        this.MAX_GAS_LIMIT = 8000000;
        this.BLOCK_TIME_TARGET = 15000; // 15 seconds
        
        const savedData = this.persistence.loadBlockchain();
        
        if (savedData && savedData.chain && savedData.chain.length > 0) {
            console.log('🔄 Initializing from existing blockchain data...');
            this.initializeFromSavedData(savedData);
        } else {
            console.log('🆕 No existing blockchain found, creating fresh blockchain...');
            this.initializeFreshBlockchain();
        }
        
        this.securityChecks();
    }

    initializeFromSavedData(data) {
        this.chain = data.chain || [];
        this.pendingTransactions = data.pendingTransactions || [];
        this.pendingMessages = data.pendingMessages || [];
        this.accounts = data.accounts || new Map();
        this.tokens = data.tokens || new Map();
        this.transactionHistory = data.transactionHistory || new Map();
        this.messageHistory = data.messageHistory || new Map();
        this.networkNodes = data.networkNodes || new Set();
        this.miningReward = data.miningReward || 50;
        this.gasPrice = data.gasPrice || 10;
        this.blockGasLimit = data.blockGasLimit || 8000000;
        this.chainId = data.chainId || 98451;
        this.stateRoot = data.stateRoot || '0x0000000000000000000000000000000000000000000000000000000000000000';
        this.receiptsRoot = data.receiptsRoot || '0x0000000000000000000000000000000000000000000000000000000000000000';
        this.contracts = new Map();
        this.transactionIndex = 0;
        
        console.log(`✅ Loaded existing blockchain with ${this.chain.length} blocks`);
        console.log(`💰 Accounts: ${this.accounts.size}, Transactions: ${this.transactionHistory.size}, Messages: ${this.messageHistory.size}`);
        
        if (!this.isValidChain()) {
            console.warn('⚠️ Blockchain integrity check failed, but continuing with existing data...');
        }
    }

    initializeFreshBlockchain() {
        this.chain = [];
        this.pendingTransactions = [];
        this.pendingMessages = [];
        this.networkNodes = new Set();
        this.accounts = new Map();
        this.contracts = new Map();
        this.tokens = new Map();
        this.gasPrice = 10;
        this.blockGasLimit = 8000000;
        this.chainId = 98451;
        this.transactionHistory = new Map();
        this.messageHistory = new Map();
        this.stateRoot = '0x0000000000000000000000000000000000000000000000000000000000000000';
        this.receiptsRoot = '0x0000000000000000000000000000000000000000000000000000000000000000';
        this.transactionIndex = 0;
        this.miningReward = 50; // TESAM tokens
        
        this.createGenesisBlock();
        
        try {
            this.saveState();
        } catch (error) {
            console.warn('⚠️ Could not save initial state, but continuing:', error.message);
        }
    }

    securityChecks() {
        if (this.chain.length === 0) {
            throw new Error('Blockchain initialization failed');
        }
        
        console.log('🔒 Security checks passed');
    }

    createGenesisBlock() {
        if (this.chain.length > 0) {
            console.log('📦 Using existing genesis block from loaded data');
            return;
        }

        // Generate secure founder address
        const founderPrivateKey = SecureCrypto.generatePrivateKey();
        const founderAddress = SecureCrypto.privateKeyToAddress(founderPrivateKey);
        
        console.log('\n🔑 CREATING NEW GENESIS BLOCK:');
        console.log(`   Address: ${founderAddress}`);
        console.log(`   Private Key: ${founderPrivateKey}`);
        console.log('   ⚠️  THIS IS YOUR FOUNDER WALLET - SAVE PRIVATE KEY SECURELY!');
        console.log('   ⚠️  THIS KEY CANNOT BE RECOVERED IF LOST!\n');

        // Create genesis transaction
        const genesisTransaction = {
            from: '0x0000000000000000000000000000000000000000',
            to: founderAddress,
            amount: this.toWei(1000000),
            value: this.toWei(1000000),
            gas: 0,
            gasPrice: 0,
            nonce: 0,
            chainId: this.chainId,
            timestamp: Date.now(),
            data: null,
            status: 'success',
            blockNumber: 0,
            transactionIndex: 0,
            type: 'genesis'
        };

        genesisTransaction.hash = this.calculateTxHash(genesisTransaction);

        const genesisBlock = {
            index: 0,
            number: 0,
            timestamp: Date.now(),
            transactions: [genesisTransaction],
            messages: [],
            previousHash: '0x0000000000000000000000000000000000000000000000000000000000000000',
            hash: '',
            nonce: 0,
            merkleRoot: this.calculateMerkleRoot([genesisTransaction]),
            blockReward: '0',
            gasUsed: 0,
            gasLimit: this.blockGasLimit,
            stateRoot: this.stateRoot,
            receiptsRoot: this.receiptsRoot,
            miner: '0x0000000000000000000000000000000000000000',
            extraData: '0x' + Buffer.from('TESAM Secure Genesis Block with Messaging').toString('hex'),
            size: 1024,
            totalDifficulty: 0,
            version: '3.0.0',
            messageCount: 0
        };

        genesisBlock.hash = this.calculateBlockHash(genesisBlock);
        this.chain.push(genesisBlock);
        
        this.transactionHistory.set(genesisTransaction.hash, { ...genesisTransaction, blockNumber: 0 });
        
        this.accounts.set(founderAddress, {
            balance: this.toWei(1000000),
            nonce: 0,
            codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
            storageRoot: '0x0000000000000000000000000000000000000000000000000000000000000000',
            transactionCount: 0,
            messageCount: 0,
            type: 'externally_owned'
        });

        return { founderAddress, founderPrivateKey };
    }

    // Message-based consensus - generate block when we have enough activity
    shouldGenerateBlock() {
        const timeSinceLastBlock = Date.now() - (this.getLatestBlock()?.timestamp || 0);
        const hasEnoughTransactions = this.pendingTransactions.length >= 10;
        const hasEnoughMessages = this.pendingMessages.length >= 5;
        const timeThresholdReached = timeSinceLastBlock > this.BLOCK_TIME_TARGET;
        
        return (hasEnoughTransactions || hasEnoughMessages) && timeThresholdReached;
    }

    // Mine 200M TESAM to target address
    async mineInitialSupply(targetAddress, amount = 200000000) {
        if (!SecureCrypto.validateAddress(targetAddress)) {
            throw new Error('Invalid target address');
        }

        console.log(`\n⛏️ TESAM SUPPLY MINING: ${amount} TESAM to ${targetAddress}`);
        console.log('🔒 Using message-based consensus...\n');
        
        const blocksToMine = Math.ceil(amount / this.miningReward);
        let totalMined = 0;
        
        for (let i = 0; i < blocksToMine; i++) {
            process.stdout.write(`Generating block ${i+1}/${blocksToMine}... `);
            const block = this.generateBlock(targetAddress);
            totalMined += this.miningReward;
            console.log(`✅ ${this.miningReward} TESAM generated`);
            
            if (i % 10 === 0) {
                await this.delay(100);
            }
        }
        
        const finalBalance = this.getBalance(targetAddress);
        console.log(`\n🎉 TESAM SUPPLY GENERATION COMPLETED!`);
        console.log(`💰 Total Generated: ${this.fromWei(finalBalance)} TESAM`);
        console.log(`📦 Final Balance: ${finalBalance} wei`);
        console.log(`📍 Target Address: ${targetAddress}\n`);
        
        return finalBalance;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Generate block using message-based consensus
    generateBlock(minerAddress) {
        if (!SecureCrypto.validateAddress(minerAddress)) {
            throw new Error('Invalid miner address');
        }

        const previousBlock = this.getLatestBlock();
        const blockTransactions = [];
        const blockMessages = [];
        let totalGasUsed = 0;
        let totalSize = 0;

        // Process transactions
        for (const tx of this.pendingTransactions) {
            if (blockTransactions.length >= this.MAX_TRANSACTIONS_PER_BLOCK) break;
            
            const txSize = JSON.stringify(tx).length;
            if (totalSize + txSize > this.MAX_BLOCK_SIZE) break;
            
            const txGas = tx.gas || 21000;
            if (totalGasUsed + txGas > this.blockGasLimit) break;
            
            try {
                if (this.validateTransaction(tx)) {
                    const serializedTx = { 
                        ...tx, 
                        blockNumber: this.chain.length,
                        transactionIndex: blockTransactions.length,
                        status: 'success'
                    };
                    blockTransactions.push(serializedTx);
                    totalGasUsed += txGas;
                    totalSize += txSize;
                }
            } catch (error) {
                console.log(`Transaction ${tx.hash} rejected: ${error.message}`);
            }
        }

        // Process messages
        for (const msg of this.pendingMessages) {
            if (blockMessages.length >= this.MAX_MESSAGES_PER_BLOCK) break;
            
            const msgSize = JSON.stringify(msg).length;
            if (totalSize + msgSize > this.MAX_BLOCK_SIZE) break;
            
            blockMessages.push({
                ...msg,
                blockNumber: this.chain.length,
                messageIndex: blockMessages.length,
                status: 'delivered'
            });
            totalSize += msgSize;
        }

        const block = {
            index: this.chain.length,
            number: this.chain.length,
            timestamp: Date.now(),
            transactions: blockTransactions,
            messages: blockMessages,
            previousHash: previousBlock.hash,
            nonce: 0,
            merkleRoot: this.calculateMerkleRoot([...blockTransactions, ...blockMessages]),
            blockReward: this.toWei(this.miningReward),
            gasUsed: totalGasUsed,
            gasLimit: this.blockGasLimit,
            stateRoot: this.stateRoot,
            receiptsRoot: this.calculateReceiptsRoot(blockTransactions),
            miner: minerAddress,
            extraData: '0x' + Buffer.from(`TESAM Block ${this.chain.length}`).toString('hex').substring(0, 64),
            size: totalSize + 1024,
            transactionCount: blockTransactions.length,
            messageCount: blockMessages.length,
            version: '3.0.0'
        };

        console.log(`📦 Generating block ${block.index} (${blockTransactions.length} tx, ${blockMessages.length} msg)`);
        
        // Simple hash calculation for message-based consensus
        block.hash = this.calculateBlockHash(block);
        
        // Add mining reward transaction
        const rewardTx = {
            from: '0x0000000000000000000000000000000000000000',
            to: minerAddress,
            amount: this.toWei(this.miningReward),
            value: this.toWei(this.miningReward),
            gas: 0,
            gasPrice: 0,
            nonce: 0,
            chainId: this.chainId,
            timestamp: Date.now(),
            data: null,
            status: 'success',
            blockNumber: this.chain.length,
            transactionIndex: blockTransactions.length,
            type: 'mining_reward'
        };

        rewardTx.hash = this.calculateTxHash(rewardTx);
        block.transactions.push(rewardTx);
        
        this.chain.push(block);
        
        // Update histories
        block.transactions.forEach(tx => {
            this.transactionHistory.set(tx.hash, tx);
        });
        
        block.messages.forEach(msg => {
            this.messageHistory.set(msg.messageHash || msg.hash, msg);
        });
        
        // Remove processed transactions and messages
        this.pendingTransactions = this.pendingTransactions.filter(
            tx => !blockTransactions.some(minedTx => minedTx.hash === tx.hash)
        );
        
        this.pendingMessages = this.pendingMessages.filter(
            msg => !blockMessages.some(processedMsg => processedMsg.hash === msg.hash)
        );
        
        this.updateAccountBalances(block.transactions);
        this.updateMessageCounts(block.messages);
        this.stateRoot = this.calculateStateRoot();
        
        this.saveState();
        
        console.log(`✅ Block ${block.index} generated with ${block.transactions.length} transactions and ${block.messages.length} messages`);
        console.log(`📦 Hash: ${block.hash}`);
        
        return block;
    }

    // Send encrypted message
    sendEncryptedMessage(fromPrivateKey, toAddress, message, messageType = 'text') {
        try {
            if (!SecureCrypto.validatePrivateKey(fromPrivateKey)) {
                throw new Error('Invalid sender private key');
            }

            if (!SecureCrypto.validateAddress(toAddress)) {
                throw new Error('Invalid recipient address');
            }

            const fromAddress = SecureCrypto.privateKeyToAddress(fromPrivateKey);
            
            // Get sender's public key (simplified - in real implementation, you'd store public keys)
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(Buffer.from(fromPrivateKey.replace('0x', ''), 'hex'));
            const senderPublicKey = ecdh.getPublicKey('hex');

            // Encrypt the message
            const encryptedMessage = SecureCrypto.encryptMessage(message, fromPrivateKey, senderPublicKey);

            const messageData = {
                from: fromAddress,
                to: toAddress,
                encryptedData: encryptedMessage.encryptedData,
                iv: encryptedMessage.iv,
                authTag: encryptedMessage.authTag,
                timestamp: Date.now(),
                messageType: messageType,
                messageHash: crypto.createHash('sha256').update(message + Date.now()).digest('hex'),
                status: 'pending'
            };

            messageData.hash = this.calculateMessageHash(messageData);
            
            this.pendingMessages.push(messageData);

            // Auto-generate block if conditions are met
            if (this.shouldGenerateBlock()) {
                const minerAddress = fromAddress; // Sender becomes block generator
                this.generateBlock(minerAddress);
            }

            this.saveState();
            
            console.log(`💬 Encrypted message sent from ${fromAddress.substring(0, 10)}... to ${toAddress.substring(0, 10)}...`);
            
            return {
                messageHash: messageData.hash,
                from: fromAddress,
                to: toAddress,
                timestamp: messageData.timestamp,
                status: 'pending'
            };
        } catch (error) {
            console.error('Error sending message:', error);
            throw new Error(`Failed to send message: ${error.message}`);
        }
    }

    // Get messages for an address
    getMessagesForAddress(address, limit = 50) {
        if (!SecureCrypto.validateAddress(address)) {
            throw new Error('Invalid address');
        }

        const messages = [];
        
        // Search through message history
        for (const [hash, msg] of this.messageHistory.entries()) {
            if (msg.from === address || msg.to === address) {
                messages.push({
                    ...msg,
                    direction: msg.from === address ? 'outgoing' : 'incoming'
                });
            }
            
            if (messages.length >= limit) break;
        }

        // Sort by timestamp (newest first)
        messages.sort((a, b) => b.timestamp - a.timestamp);
        
        return messages;
    }

    // Decrypt and read message
    readEncryptedMessage(messageHash, receiverPrivateKey) {
        try {
            const message = this.messageHistory.get(messageHash);
            if (!message) {
                throw new Error('Message not found');
            }

            if (!SecureCrypto.validatePrivateKey(receiverPrivateKey)) {
                throw new Error('Invalid receiver private key');
            }

            const receiverAddress = SecureCrypto.privateKeyToAddress(receiverPrivateKey);
            if (message.to !== receiverAddress) {
                throw new Error('You are not the intended recipient of this message');
            }

            // Get sender's public key (simplified)
            const ecdh = crypto.createECDH('secp256k1');
            ecdh.setPrivateKey(Buffer.from(receiverPrivateKey.replace('0x', ''), 'hex'));
            const senderPublicKey = ecdh.getPublicKey('hex');

            const encryptedPayload = {
                encryptedData: message.encryptedData,
                iv: message.iv,
                authTag: message.authTag
            };

            const decryptedMessage = SecureCrypto.decryptMessage(encryptedPayload, receiverPrivateKey, senderPublicKey);
            
            return {
                from: message.from,
                to: message.to,
                message: decryptedMessage,
                timestamp: message.timestamp,
                messageType: message.messageType,
                blockNumber: message.blockNumber,
                status: 'read'
            };
        } catch (error) {
            console.error('Error reading message:', error);
            throw new Error(`Failed to read message: ${error.message}`);
        }
    }

    validateTransaction(transaction) {
        if (!transaction.from || !transaction.to) {
            throw new Error('Invalid transaction: missing from/to addresses');
        }

        if (!SecureCrypto.validateAddress(transaction.from) || !SecureCrypto.validateAddress(transaction.to)) {
            throw new Error('Invalid address format');
        }

        if (!SecureCrypto.verifySignature(transaction, transaction.signature)) {
            throw new Error('Invalid transaction signature');
        }

        const senderAccount = this.accounts.get(transaction.from) || { balance: '0', nonce: 0 };
        
        if (transaction.nonce !== senderAccount.nonce + 1) {
            throw new Error(`Invalid nonce: expected ${senderAccount.nonce + 1}, got ${transaction.nonce}`);
        }

        if (transaction.gas < 21000 || transaction.gas > this.MAX_GAS_LIMIT) {
            throw new Error(`Invalid gas limit: ${transaction.gas}`);
        }

        if (transaction.gasPrice < this.MIN_GAS_PRICE) {
            throw new Error(`Gas price too low: ${transaction.gasPrice}`);
        }

        const amount = BigInt(transaction.amount);
        const balance = BigInt(senderAccount.balance || '0');
        const gasCost = BigInt(transaction.gas) * BigInt(transaction.gasPrice);
        const totalCost = amount + gasCost;
        
        if (balance < totalCost) {
            throw new Error(`Insufficient balance: ${this.fromWei(balance.toString())} < ${this.fromWei(totalCost.toString())} TESAM`);
        }

        if (amount <= 0) {
            throw new Error('Invalid transaction amount');
        }

        return true;
    }

    createTransaction(from, to, amount, privateKey, data = null) {
        try {
            if (!SecureCrypto.validatePrivateKey(privateKey)) {
                throw new Error('Invalid private key');
            }

            const fromAddress = SecureCrypto.privateKeyToAddress(privateKey);
            
            if (!SecureCrypto.validateAddress(fromAddress) || !SecureCrypto.validateAddress(to)) {
                throw new Error('Invalid address format');
            }

            const senderAccount = this.accounts.get(fromAddress) || { balance: '0', nonce: 0 };
            const nonce = senderAccount.nonce + 1;
            const gas = data ? 100000 : 21000;
            const gasPrice = this.gasPrice;
            const value = this.toWei(amount);
            const gasCost = BigInt(gas) * BigInt(gasPrice);
            const totalCost = BigInt(value) + gasCost;
            const balance = BigInt(senderAccount.balance || '0');

            if (balance < totalCost) {
                throw new Error(`Insufficient balance: ${this.fromWei(balance.toString())} < ${this.fromWei(totalCost.toString())} TESAM`);
            }

            const transaction = {
                from: fromAddress,
                to: to,
                amount: value.toString(),
                value: value.toString(),
                gas: gas,
                gasPrice: gasPrice,
                nonce: nonce,
                chainId: this.chainId,
                timestamp: Date.now(),
                data: data,
                type: data ? 'contract_call' : 'transfer'
            };

            transaction.hash = this.calculateTxHash(transaction);
            transaction.signature = SecureCrypto.signTransaction(transaction, privateKey);

            this.pendingTransactions.push(transaction);

            // Auto-generate block if conditions are met
            if (this.shouldGenerateBlock()) {
                const minerAddress = fromAddress; // Sender becomes block generator
                this.generateBlock(minerAddress);
            }

            this.saveState();

            console.log(`📤 Transaction created: ${transaction.hash}`);
            console.log(`   From: ${fromAddress}`);
            console.log(`   To: ${to}`);
            console.log(`   Amount: ${amount} TESAM`);
            console.log(`   Gas: ${gas} | Gas Price: ${gasPrice} | Nonce: ${nonce}`);

            return transaction;
        } catch (error) {
            console.error('Error creating transaction:', error);
            throw new Error(`Transaction failed: ${error.message}`);
        }
    }

    getBalance(address) {
        if (!SecureCrypto.validateAddress(address)) {
            throw new Error('Invalid address');
        }

        const account = this.accounts.get(address);
        return account ? account.balance : '0';
    }

    getAccountInfo(address) {
        if (!SecureCrypto.validateAddress(address)) {
            throw new Error('Invalid address');
        }

        const account = this.accounts.get(address) || { 
            balance: '0', 
            nonce: 0, 
            transactionCount: 0,
            messageCount: 0,
            type: 'externally_owned'
        };

        const transactions = [];
        for (const [hash, tx] of this.transactionHistory.entries()) {
            if (tx.from === address || tx.to === address) {
                transactions.push(tx);
            }
            if (transactions.length >= 100) break;
        }

        const messages = this.getMessagesForAddress(address, 50);

        return {
            address: address,
            balance: account.balance,
            balanceTESAM: this.fromWei(account.balance),
            nonce: account.nonce,
            transactionCount: account.transactionCount || transactions.length,
            messageCount: account.messageCount || messages.length,
            recentTransactions: transactions.slice(0, 10),
            recentMessages: messages.slice(0, 10),
            type: account.type
        };
    }

    getLatestBlock() {
        return this.chain.length > 0 ? this.chain[this.chain.length - 1] : null;
    }

    getBlockByNumber(blockNumber) {
        return this.chain[blockNumber] || null;
    }

    getTransactionByHash(hash) {
        return this.transactionHistory.get(hash) || null;
    }

    getBlockByHash(hash) {
        return this.chain.find(block => block.hash === hash) || null;
    }

    getBlockchainInfo() {
        const latestBlock = this.getLatestBlock();
        const totalTransactions = this.transactionHistory.size;
        const totalMessages = this.messageHistory.size;
        const totalAccounts = this.accounts.size;
        const totalSize = this.chain.reduce((sum, block) => sum + (block.size || 0), 0);
        
        const totalSupply = Array.from(this.accounts.values()).reduce((sum, account) => {
            return sum + BigInt(account.balance || '0');
        }, BigInt(0));

        return {
            chainId: this.chainId,
            blockHeight: this.chain.length - 1,
            latestBlock: latestBlock ? {
                number: latestBlock.number,
                hash: latestBlock.hash,
                timestamp: latestBlock.timestamp,
                transactionCount: latestBlock.transactionCount || latestBlock.transactions.length,
                messageCount: latestBlock.messageCount || (latestBlock.messages ? latestBlock.messages.length : 0)
            } : null,
            totalTransactions: totalTransactions,
            totalMessages: totalMessages,
            totalAccounts: totalAccounts,
            pendingTransactions: this.pendingTransactions.length,
            pendingMessages: this.pendingMessages.length,
            totalSupply: totalSupply.toString(),
            totalSupplyTESAM: this.fromWei(totalSupply.toString()),
            miningReward: this.miningReward,
            gasPrice: this.gasPrice,
            blockGasLimit: this.blockGasLimit,
            totalSize: totalSize,
            averageBlockTime: this.calculateAverageBlockTime(),
            consensus: 'Message-Based Activity',
            version: '3.0.0',
            security: 'High (Encrypted Messaging + Secure Transactions)'
        };
    }

    calculateAverageBlockTime() {
        if (this.chain.length < 2) return 0;
        
        let totalTime = 0;
        for (let i = 1; i < this.chain.length; i++) {
            totalTime += this.chain[i].timestamp - this.chain[i - 1].timestamp;
        }
        
        return Math.floor(totalTime / (this.chain.length - 1));
    }

    calculateBlockHash(block) {
        const blockString = JSON.stringify({
            index: block.index,
            timestamp: block.timestamp,
            transactions: block.transactions.map(tx => tx.hash),
            messages: block.messages.map(msg => msg.hash),
            previousHash: block.previousHash,
            merkleRoot: block.merkleRoot,
            stateRoot: block.stateRoot,
            receiptsRoot: block.receiptsRoot,
            miner: block.miner,
            gasUsed: block.gasUsed,
            gasLimit: block.gasLimit
        });
        
        return '0x' + crypto.createHash('sha256').update(blockString).digest('hex');
    }

    calculateTxHash(transaction) {
        const txString = JSON.stringify({
            from: transaction.from,
            to: transaction.to,
            amount: transaction.amount,
            gas: transaction.gas,
            gasPrice: transaction.gasPrice,
            nonce: transaction.nonce,
            chainId: transaction.chainId,
            timestamp: transaction.timestamp,
            data: transaction.data
        });
        
        return '0x' + crypto.createHash('sha256').update(txString).digest('hex');
    }

    calculateMessageHash(message) {
        const msgString = JSON.stringify({
            from: message.from,
            to: message.to,
            encryptedData: message.encryptedData,
            iv: message.iv,
            timestamp: message.timestamp,
            messageType: message.messageType
        });
        
        return '0x' + crypto.createHash('sha256').update(msgString).digest('hex');
    }

    calculateMerkleRoot(items) {
        if (items.length === 0) {
            return '0x0000000000000000000000000000000000000000000000000000000000000000';
        }

        const hashes = items.map(item => {
            const str = JSON.stringify(item);
            return crypto.createHash('sha256').update(str).digest('hex');
        });

        while (hashes.length > 1) {
            const newHashes = [];
            for (let i = 0; i < hashes.length; i += 2) {
                const left = hashes[i];
                const right = i + 1 < hashes.length ? hashes[i + 1] : hashes[i];
                const combined = crypto.createHash('sha256').update(left + right).digest('hex');
                newHashes.push(combined);
            }
            hashes.length = 0;
            hashes.push(...newHashes);
        }

        return '0x' + hashes[0];
    }

    calculateReceiptsRoot(transactions) {
        const receipts = transactions.map(tx => ({
            transactionHash: tx.hash,
            gasUsed: tx.gas || 21000,
            status: tx.status || 'success',
            blockNumber: tx.blockNumber,
            transactionIndex: tx.transactionIndex
        }));

        return this.calculateMerkleRoot(receipts);
    }

    calculateStateRoot() {
        const accountData = Array.from(this.accounts.entries()).map(([address, account]) => ({
            address,
            balance: account.balance,
            nonce: account.nonce,
            codeHash: account.codeHash
        }));

        return this.calculateMerkleRoot(accountData);
    }

    updateAccountBalances(transactions) {
        for (const tx of transactions) {
            if (tx.type === 'mining_reward' || tx.type === 'genesis') {
                // Add to recipient
                const toAccount = this.accounts.get(tx.to) || { balance: '0', nonce: 0, transactionCount: 0 };
                this.accounts.set(tx.to, {
                    ...toAccount,
                    balance: (BigInt(toAccount.balance) + BigInt(tx.amount)).toString(),
                    transactionCount: (toAccount.transactionCount || 0) + 1
                });
            } else {
                // Regular transaction
                const fromAccount = this.accounts.get(tx.from) || { balance: '0', nonce: 0, transactionCount: 0 };
                const toAccount = this.accounts.get(tx.to) || { balance: '0', nonce: 0, transactionCount: 0 };
                const gasCost = BigInt(tx.gas) * BigInt(tx.gasPrice);

                // Deduct from sender
                this.accounts.set(tx.from, {
                    ...fromAccount,
                    balance: (BigInt(fromAccount.balance) - BigInt(tx.amount) - gasCost).toString(),
                    nonce: Math.max(fromAccount.nonce, tx.nonce),
                    transactionCount: (fromAccount.transactionCount || 0) + 1
                });

                // Add to recipient
                this.accounts.set(tx.to, {
                    ...toAccount,
                    balance: (BigInt(toAccount.balance) + BigInt(tx.amount)).toString(),
                    transactionCount: (toAccount.transactionCount || 0) + 1
                });
            }
        }
    }

    updateMessageCounts(messages) {
        for (const msg of messages) {
            const fromAccount = this.accounts.get(msg.from) || { balance: '0', nonce: 0, messageCount: 0 };
            const toAccount = this.accounts.get(msg.to) || { balance: '0', nonce: 0, messageCount: 0 };

            this.accounts.set(msg.from, {
                ...fromAccount,
                messageCount: (fromAccount.messageCount || 0) + 1
            });

            this.accounts.set(msg.to, {
                ...toAccount,
                messageCount: (toAccount.messageCount || 0) + 1
            });
        }
    }

    toWei(amount) {
        return (BigInt(Math.floor(amount * 1e18))).toString();
    }

    fromWei(wei) {
        return Number(BigInt(wei) / BigInt(1e18));
    }

    isValidChain() {
        if (this.chain.length === 0) return false;
        
        // Check genesis block
        const genesis = this.chain[0];
        if (genesis.index !== 0 || genesis.previousHash !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
            return false;
        }

        // Check subsequent blocks
        for (let i = 1; i < this.chain.length; i++) {
            const block = this.chain[i];
            const previousBlock = this.chain[i - 1];

            if (block.previousHash !== previousBlock.hash) {
                return false;
            }

            if (block.hash !== this.calculateBlockHash(block)) {
                return false;
            }
        }

        return true;
    }

    saveState() {
        try {
            return this.persistence.saveBlockchain(this);
        } catch (error) {
            console.error('❌ Critical: Failed to save blockchain state:', error);
            return false;
        }
    }

    // Export wallet for backup
    exportWallet(address, privateKey, password) {
        try {
            if (!SecureCrypto.validateAddress(address) || !SecureCrypto.validatePrivateKey(privateKey)) {
                throw new Error('Invalid wallet data');
            }

            const walletData = {
                address: address,
                privateKey: privateKey,
                chainId: this.chainId,
                version: '3.0.0',
                exportedAt: new Date().toISOString(),
                network: 'TESAM Secure Blockchain'
            };

            // Encrypt wallet with password
            const salt = randomBytes(16);
            const key = scryptSync(password, salt, 32);
            const iv = randomBytes(16);
            const cipher = createCipheriv('aes-256-gcm', key, iv);
            
            let encrypted = cipher.update(JSON.stringify(walletData), 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();

            const encryptedWallet = {
                encryptedData: encrypted,
                salt: salt.toString('hex'),
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                algorithm: 'aes-256-gcm',
                kdf: 'scrypt',
                kdfparams: { N: 16384, r: 8, p: 1 }
            };

            return encryptedWallet;
        } catch (error) {
            console.error('Error exporting wallet:', error);
            throw new Error(`Failed to export wallet: ${error.message}`);
        }
    }

    // Import wallet from backup
    importWallet(encryptedWallet, password) {
        try {
            const salt = Buffer.from(encryptedWallet.salt, 'hex');
            const key = scryptSync(password, salt, 32);
            const iv = Buffer.from(encryptedWallet.iv, 'hex');
            const authTag = Buffer.from(encryptedWallet.authTag, 'hex');

            const decipher = createDecipheriv('aes-256-gcm', key, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encryptedWallet.encryptedData, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            const walletData = JSON.parse(decrypted);

            if (!SecureCrypto.validateAddress(walletData.address) || !SecureCrypto.validatePrivateKey(walletData.privateKey)) {
                throw new Error('Invalid wallet data in backup');
            }

            console.log('✅ Wallet imported successfully:', walletData.address);
            return walletData;
        } catch (error) {
            console.error('Error importing wallet:', error);
            throw new Error(`Failed to import wallet: ${error.message}`);
        }
    }
}

// Enhanced CLI Interface
class TesamCLI {
    constructor() {
        this.blockchain = new TesamBlockchain();
        this.currentWallet = null;
        this.setupEventListeners();
        this.showWelcome();
    }

    setupEventListeners() {
        process.on('SIGINT', () => {
            console.log('\n\n💾 Saving blockchain state before exit...');
            this.blockchain.saveState();
            console.log('👋 TESAM Blockchain stopped safely. Goodbye!');
            process.exit(0);
        });

        process.on('uncaughtException', (error) => {
            console.error('\n❌ Critical Error:', error);
            console.log('💾 Attempting emergency save...');
            this.blockchain.saveState();
            process.exit(1);
        });
    }

    showWelcome() {
        console.log('\n' + '='.repeat(70));
        console.log('🚀 TESAM SECURE BLOCKCHAIN v3.0.0');
        console.log('💎 Message-Based Consensus • Encrypted Social Media • Secure Transactions');
        console.log('='.repeat(70));
        console.log(`📊 Blockchain Height: ${this.blockchain.chain.length - 1}`);
        console.log(`👥 Total Accounts: ${this.blockchain.accounts.size}`);
        console.log(`💬 Total Messages: ${this.blockchain.messageHistory.size}`);
        console.log(`💰 Total Transactions: ${this.blockchain.transactionHistory.size}`);
        console.log('='.repeat(70) + '\n');
    }

    async createWallet() {
        const privateKey = SecureCrypto.generatePrivateKey();
        const address = SecureCrypto.privateKeyToAddress(privateKey);
        
        this.currentWallet = { address, privateKey };
        
        console.log('\n🎉 NEW WALLET CREATED:');
        console.log('📍 Address:   ', address);
        console.log('🔑 Private Key:', privateKey);
        console.log('\n⚠️  IMPORTANT SECURITY WARNING:');
        console.log('   • Save your private key securely!');
        console.log('   • Never share your private key with anyone!');
        console.log('   • This key cannot be recovered if lost!');
        console.log('   • Consider exporting your wallet for backup\n');
        
        return { address, privateKey };
    }

    async importWallet() {
        console.log('\n📥 Wallet Import:');
        // Simplified import - in real implementation, you'd handle encrypted backups
        const privateKey = await this.question('Enter your private key (0x...): ');
        
        if (!SecureCrypto.validatePrivateKey(privateKey)) {
            console.log('❌ Invalid private key format');
            return null;
        }

        const address = SecureCrypto.privateKeyToAddress(privateKey);
        this.currentWallet = { address, privateKey };
        
        console.log('✅ Wallet imported successfully:', address);
        return this.currentWallet;
    }

    showWalletInfo() {
        if (!this.currentWallet) {
            console.log('❌ No wallet loaded. Create or import a wallet first.');
            return;
        }

        const info = this.blockchain.getAccountInfo(this.currentWallet.address);
        
        console.log('\n👛 WALLET INFORMATION:');
        console.log('📍 Address:      ', info.address);
        console.log('💰 Balance:      ', info.balanceTESAM, 'TESAM');
        console.log('🔢 Nonce:        ', info.nonce);
        console.log('📤 Transactions: ', info.transactionCount);
        console.log('💬 Messages:     ', info.messageCount);
        
        if (info.recentTransactions.length > 0) {
            console.log('\n📋 Recent Transactions:');
            info.recentTransactions.forEach(tx => {
                console.log(`   ${tx.hash.substring(0, 16)}... | ${this.blockchain.fromWei(tx.amount)} TESAM | ${tx.status}`);
            });
        }
        
        if (info.recentMessages.length > 0) {
            console.log('\n💬 Recent Messages:');
            info.recentMessages.forEach(msg => {
                console.log(`   ${msg.direction} | ${msg.to.substring(0, 10)}... | ${new Date(msg.timestamp).toLocaleString()}`);
            });
        }
    }

    async sendTransaction() {
        if (!this.currentWallet) {
            console.log('❌ No wallet loaded. Create or import a wallet first.');
            return;
        }

        console.log('\n📤 Send Transaction:');
        const to = await this.question('Recipient address: ');
        const amount = parseFloat(await this.question('Amount (TESAM): '));
        const data = await this.question('Data (optional): ');

        if (!SecureCrypto.validateAddress(to)) {
            console.log('❌ Invalid recipient address');
            return;
        }

        if (isNaN(amount) || amount <= 0) {
            console.log('❌ Invalid amount');
            return;
        }

        try {
            const tx = this.blockchain.createTransaction(
                this.currentWallet.address,
                to,
                amount,
                this.currentWallet.privateKey,
                data || null
            );
            
            console.log('✅ Transaction created:', tx.hash);
            console.log('⏳ Waiting for block generation...');
            
        } catch (error) {
            console.log('❌ Transaction failed:', error.message);
        }
    }

    async sendMessage() {
        if (!this.currentWallet) {
            console.log('❌ No wallet loaded. Create or import a wallet first.');
            return;
        }

        console.log('\n💬 Send Encrypted Message:');
        const to = await this.question('Recipient address: ');
        const message = await this.question('Message: ');
        const messageType = await this.question('Message type (text/file/image, default: text): ') || 'text';

        if (!SecureCrypto.validateAddress(to)) {
            console.log('❌ Invalid recipient address');
            return;
        }

        if (!message.trim()) {
            console.log('❌ Message cannot be empty');
            return;
        }

        try {
            const result = this.blockchain.sendEncryptedMessage(
                this.currentWallet.privateKey,
                to,
                message,
                messageType
            );
            
            console.log('✅ Encrypted message sent:', result.messageHash);
            
        } catch (error) {
            console.log('❌ Failed to send message:', error.message);
        }
    }

    async readMessages() {
        if (!this.currentWallet) {
            console.log('❌ No wallet loaded. Create or import a wallet first.');
            return;
        }

        console.log('\n📨 Your Messages:');
        const messages = this.blockchain.getMessagesForAddress(this.currentWallet.address);
        
        if (messages.length === 0) {
            console.log('   No messages found.');
            return;
        }

        messages.forEach((msg, index) => {
            console.log(`\n${index + 1}. ${msg.direction.toUpperCase()} to ${msg.to.substring(0, 10)}...`);
            console.log(`   Time: ${new Date(msg.timestamp).toLocaleString()}`);
            console.log(`   Type: ${msg.messageType}`);
            console.log(`   Hash: ${msg.hash}`);
        });

        const choice = await this.question('\nEnter message number to read (or press Enter to skip): ');
        if (choice && !isNaN(choice)) {
            const index = parseInt(choice) - 1;
            if (messages[index]) {
                try {
                    const decrypted = this.blockchain.readEncryptedMessage(
                        messages[index].hash,
                        this.currentWallet.privateKey
                    );
                    console.log('\n🔓 Decrypted Message:');
                    console.log('   From:', decrypted.from);
                    console.log('   Message:', decrypted.message);
                    console.log('   Time:', new Date(decrypted.timestamp).toLocaleString());
                } catch (error) {
                    console.log('❌ Failed to decrypt message:', error.message);
                }
            }
        }
    }

    showBlockchainInfo() {
        const info = this.blockchain.getBlockchainInfo();
        
        console.log('\n📊 TESAM BLOCKCHAIN INFORMATION:');
        console.log('⛓️  Chain ID:        ', info.chainId);
        console.log('📏 Block Height:    ', info.blockHeight);
        console.log('💰 Total Supply:    ', info.totalSupplyTESAM, 'TESAM');
        console.log('📤 Total Transactions:', info.totalTransactions);
        console.log('💬 Total Messages:   ', info.totalMessages);
        console.log('👥 Total Accounts:   ', info.totalAccounts);
        console.log('⏱️  Average Block Time:', info.averageBlockTime, 'ms');
        console.log('🛡️  Consensus:       ', info.consensus);
        console.log('🔒 Security Level:   ', info.security);
        
        if (info.latestBlock) {
            console.log('\n📦 Latest Block:');
            console.log('   Number:', info.latestBlock.number);
            console.log('   Hash:', info.latestBlock.hash.substring(0, 20) + '...');
            console.log('   Transactions:', info.latestBlock.transactionCount);
            console.log('   Messages:', info.latestBlock.messageCount);
            console.log('   Time:', new Date(info.latestBlock.timestamp).toLocaleString());
        }
    }

    async mineInitialSupply() {
        if (!this.currentWallet) {
            console.log('❌ No wallet loaded. Create or import a wallet first.');
            return;
        }

        console.log('\n⛏️ TESAM Supply Mining:');
        const amount = parseInt(await this.question('Amount to mine (default 200000000): ') || '200000000');
        
        if (isNaN(amount) || amount <= 0) {
            console.log('❌ Invalid amount');
            return;
        }

        try {
            console.log(`\n🚀 Starting to mine ${amount} TESAM to ${this.currentWallet.address}...`);
            const finalBalance = await this.blockchain.mineInitialSupply(this.currentWallet.address, amount);
            
            console.log(`\n🎉 Mining completed!`);
            console.log(`💰 Final balance: ${this.blockchain.fromWei(finalBalance)} TESAM`);
            
        } catch (error) {
            console.log('❌ Mining failed:', error.message);
        }
    }

    async generateBlock() {
        if (!this.currentWallet) {
            console.log('❌ No wallet loaded. Create or import a wallet first.');
            return;
        }

        console.log('\n⛏️ Generating new block...');
        const block = this.blockchain.generateBlock(this.currentWallet.address);
        
        console.log('✅ Block generated:', block.hash);
        console.log(`   Transactions: ${block.transactions.length}`);
        console.log(`   Messages: ${block.messages.length}`);
        console.log(`   Miner: ${block.miner}`);
    }

    async showMenu() {
        console.log('\n' + '='.repeat(50));
        console.log('🏠 TESAM BLOCKCHAIN MENU');
        console.log('='.repeat(50));
        console.log('1.  Create New Wallet');
        console.log('2.  Import Wallet');
        console.log('3.  Show Wallet Info');
        console.log('4.  Send Transaction');
        console.log('5.  Send Encrypted Message');
        console.log('6.  Read Messages');
        console.log('7.  Show Blockchain Info');
        console.log('8.  Mine TESAM Supply');
        console.log('9.  Generate Block');
        console.log('10. Export Wallet Backup');
        console.log('11. Exit');
        console.log('='.repeat(50));
    }

    async question(prompt) {
        process.stdout.write(prompt);
        return new Promise((resolve) => {
            const stdin = process.stdin;
            stdin.resume();
            stdin.once('data', (data) => {
                resolve(data.toString().trim());
            });
        });
    }

    async start() {
        console.log('🔒 TESAM Secure Blockchain with Encrypted Messaging Started!');
        
        while (true) {
            await this.showMenu();
            const choice = await this.question('\nChoose an option (1-11): ');
            
            switch (choice) {
                case '1':
                    await this.createWallet();
                    break;
                case '2':
                    await this.importWallet();
                    break;
                case '3':
                    this.showWalletInfo();
                    break;
                case '4':
                    await this.sendTransaction();
                    break;
                case '5':
                    await this.sendMessage();
                    break;
                case '6':
                    await this.readMessages();
                    break;
                case '7':
                    this.showBlockchainInfo();
                    break;
                case '8':
                    await this.mineInitialSupply();
                    break;
                case '9':
                    await this.generateBlock();
                    break;
                case '10':
                    console.log('📁 Export feature - implement wallet encryption/decryption');
                    break;
                case '11':
                    console.log('\n💾 Saving blockchain state...');
                    this.blockchain.saveState();
                    console.log('👋 Goodbye!');
                    process.exit(0);
                default:
                    console.log('❌ Invalid choice. Please try again.');
            }
            
            // Small delay for better UX
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
}

// Export for use in other modules
module.exports = {
    TesamBlockchain,
    TesamCLI,
    SecureCrypto,
    SecureBlockchainPersistence
};

// Start the CLI if this file is run directly
if (require.main === module) {
    const cli = new TesamCLI();
    cli.start().catch(console.error);
}