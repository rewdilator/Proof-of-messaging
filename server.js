// server.js - TESAM Secure Blockchain Server with Encrypted Messaging
const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');
const crypto = require('crypto');

// Import the new TESAM blockchain
const { TesamBlockchain, SecureCrypto } = require('./advanced-chain');

// Initialize blockchain
console.log('🔒 Initializing TESAM Secure Blockchain with Encrypted Messaging...');
const blockchain = new TesamBlockchain();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Security configuration
const SECURITY_CONFIG = {
    maxTransactionsPerMinute: 100,
    maxMessagesPerMinute: 200,
    maxConnections: 1000,
    rateLimitWindow: 15 * 60 * 1000, // 15 minutes
    maxRequestsPerWindow: 1000
};

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

// CORS middleware
app.use((req, res, next) => {
    const allowedOrigins = process.env.NODE_ENV === 'production' 
        ? ['https://yourdomain.com'] 
        : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:8080'];
    
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// Simple rate limiting
const rateLimitMap = new Map();
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - SECURITY_CONFIG.rateLimitWindow;
    
    // Clean old entries
    for (let [key, value] of rateLimitMap.entries()) {
        if (value.timestamp < windowStart) {
            rateLimitMap.delete(key);
        }
    }
    
    const clientData = rateLimitMap.get(ip) || { count: 0, timestamp: now };
    
    if (clientData.count >= SECURITY_CONFIG.maxRequestsPerWindow) {
        return res.status(429).json({ error: 'Too many requests, please try again later.' });
    }
    
    clientData.count++;
    clientData.timestamp = now;
    rateLimitMap.set(ip, clientData);
    
    next();
});

// Body parsing with limits
app.use(express.json({ 
    limit: '10mb' // Increased for message data
}));

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.url} - ${req.ip}`);
    next();
});

// Input validation middleware
const validateAddress = (req, res, next) => {
    if (req.params.address && !SecureCrypto.validateAddress(req.params.address)) {
        return res.status(400).json({ error: 'Invalid address format' });
    }
    next();
};

const validatePrivateKey = (req, res, next) => {
    if (req.body.privateKey && !SecureCrypto.validatePrivateKey(req.body.privateKey)) {
        return res.status(400).json({ error: 'Invalid private key format' });
    }
    next();
};

// Static files with security headers
app.use(express.static(path.join(__dirname), {
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
    }
}));

// ========== BLOCKCHAIN API ENDPOINTS ==========

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: Date.now(),
        version: '3.0.0',
        network: 'tesam-secure',
        features: ['encrypted_messaging', 'secure_transactions', 'message_consensus']
    });
});
app.get('/messaging', (req, res) => {
    res.sendFile(path.join(__dirname, 'messager/messaging.html'));
});
// Add near the top with other imports
const BlockMonitor = require('./block-monitor');

// Add after blockchain initialization
console.log('🔍 Starting block generation monitor...');
const blockMonitor = new BlockMonitor();

// Add a new endpoint to get monitor stats
app.get('messager/monitor/stats', (req, res) => {
    try {
        const stats = blockMonitor.getStats();
        res.json({
            success: true,
            data: stats
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get monitor stats' });
    }
});
// Get blockchain statistics
app.get('/stats', (req, res) => {
    try {
        const info = blockchain.getBlockchainInfo();
        const latestBlock = blockchain.getLatestBlock();
        
        res.json({
            totalBlocks: blockchain.chain.length,
            totalTransactions: info.totalTransactions,
            totalMessages: info.totalMessages,
            totalAccounts: info.totalAccounts,
            gasPrice: info.gasPrice,
            consensus: info.consensus,
            averageBlockTime: info.averageBlockTime,
            pendingTransactions: info.pendingTransactions,
            pendingMessages: info.pendingMessages,
            chainId: info.chainId,
            latestBlockNumber: latestBlock ? latestBlock.number : 0,
            latestBlockHash: latestBlock ? latestBlock.hash : '0x0',
            totalSupply: info.totalSupplyTESAM,
            security: info.security
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Failed to get statistics' });
    }
});

// Get blockchain info
app.get('/blockchain/info', (req, res) => {
    try {
        const info = blockchain.getBlockchainInfo();
        
        res.json({
            success: true,
            data: {
                ...info,
                genesisHash: blockchain.chain[0]?.hash,
                bestBlock: blockchain.getLatestBlock()?.number
            }
        });
    } catch (error) {
        console.error('Blockchain info error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get blocks with pagination
app.get('/chain', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const page = parseInt(req.query.page) || 1;
        
        // Reverse to get latest blocks first
        const reversedChain = [...blockchain.chain].reverse();
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const paginatedBlocks = reversedChain.slice(startIndex, endIndex);
        
        res.json({
            blocks: paginatedBlocks,
            totalPages: Math.ceil(blockchain.chain.length / limit),
            currentPage: page,
            totalBlocks: blockchain.chain.length
        });
    } catch (error) {
        console.error('Chain endpoint error:', error);
        res.status(500).json({ error: 'Failed to get chain data' });
    }
});

// Search endpoint
app.get('/search/:query', (req, res) => {
    try {
        const query = req.params.query.toLowerCase();
        const results = {
            blocks: [],
            transactions: [],
            messages: [],
            addresses: [],
            tokens: []
        };

        // Search blocks by number
        if (!isNaN(query)) {
            const block = blockchain.getBlockByNumber(parseInt(query));
            if (block) results.blocks.push(block);
        }

        // Search blocks by hash
        blockchain.chain.forEach(block => {
            if (block.hash.toLowerCase().includes(query)) {
                results.blocks.push(block);
            }
        });

        // Search transactions by hash or addresses
        blockchain.chain.forEach(block => {
            if (block.transactions) {
                block.transactions.forEach(tx => {
                    if (tx.hash && tx.hash.toLowerCase().includes(query) || 
                        tx.from && tx.from.toLowerCase().includes(query) || 
                        tx.to && tx.to.toLowerCase().includes(query)) {
                        results.transactions.push({...tx, blockNumber: block.index});
                    }
                });
            }
        });

        // Search messages
        for (const [hash, message] of blockchain.messageHistory.entries()) {
            if (hash.toLowerCase().includes(query) || 
                message.from.toLowerCase().includes(query) || 
                message.to.toLowerCase().includes(query)) {
                results.messages.push({...message, messageHash: hash});
            }
        }

        // Search addresses
        if (query.startsWith('0x') && query.length === 42) {
            if (blockchain.accounts.has(query)) {
                results.addresses.push(query);
            }
        }

        // Search in account addresses
        for (let [address, account] of blockchain.accounts.entries()) {
            if (address.toLowerCase().includes(query)) {
                results.addresses.push(address);
            }
        }

        res.json(results);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Get block by number
app.get('/block/:number', (req, res) => {
    try {
        const blockNumber = parseInt(req.params.number);
        const block = blockchain.getBlockByNumber(blockNumber);
        
        if (!block) {
            return res.status(404).json({ error: 'Block not found' });
        }

        res.json(block);
    } catch (error) {
        console.error('Block endpoint error:', error);
        res.status(500).json({ error: 'Failed to get block' });
    }
});

// Get block by hash
app.get('/block/hash/:hash', (req, res) => {
    try {
        const blockHash = req.params.hash;
        if (!/^0x[a-fA-F0-9]{64}$/.test(blockHash)) {
            return res.status(400).json({ error: 'Invalid block hash format' });
        }

        const block = blockchain.getBlockByHash(blockHash);
        if (!block) {
            return res.status(404).json({ error: 'Block not found' });
        }

        res.json({
            success: true,
            data: block
        });
    } catch (error) {
        console.error('Block by hash error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get transaction by hash
app.get('/transaction/:hash', (req, res) => {
    try {
        const txHash = req.params.hash;
        if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) {
            return res.status(400).json({ error: 'Invalid transaction hash format' });
        }

        const transaction = blockchain.getTransactionByHash(txHash);
        if (!transaction) {
            return res.status(404).json({ error: 'Transaction not found' });
        }

        res.json(transaction);
    } catch (error) {
        console.error('Transaction error:', error);
        res.status(500).json({ error: 'Failed to get transaction' });
    }
});

// Get message by hash
app.get('/message/:hash', (req, res) => {
    try {
        const msgHash = req.params.hash;
        const message = blockchain.messageHistory.get(msgHash);
        
        if (!message) {
            return res.status(404).json({ error: 'Message not found' });
        }

        // Don't return encrypted data for security
        const safeMessage = {
            hash: message.hash,
            from: message.from,
            to: message.to,
            timestamp: message.timestamp,
            messageType: message.messageType,
            blockNumber: message.blockNumber,
            status: message.status
        };

        res.json(safeMessage);
    } catch (error) {
        console.error('Message error:', error);
        res.status(500).json({ error: 'Failed to get message' });
    }
});

// Get all transactions for address
app.get('/address/:address/transactions', validateAddress, (req, res) => {
    try {
        const address = req.params.address;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 25;
        
        // Get all transactions for this address
        const allTransactions = [];
        
        // Search through all blocks for transactions involving this address
        blockchain.chain.forEach(block => {
            if (block.transactions) {
                block.transactions.forEach(tx => {
                    if (tx.from === address || tx.to === address) {
                        allTransactions.push({
                            ...tx,
                            blockNumber: block.index,
                            timestamp: block.timestamp,
                            confirmations: blockchain.chain.length - block.index
                        });
                    }
                });
            }
        });

        // Sort by block number (newest first)
        allTransactions.sort((a, b) => b.blockNumber - a.blockNumber);
        
        // Paginate
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const paginatedTransactions = allTransactions.slice(startIndex, endIndex);

        res.json({
            success: true,
            data: {
                address: address,
                transactions: paginatedTransactions,
                pagination: {
                    currentPage: page,
                    totalPages: Math.ceil(allTransactions.length / limit),
                    totalTransactions: allTransactions.length,
                    hasNextPage: endIndex < allTransactions.length,
                    hasPrevPage: page > 1
                }
            }
        });
    } catch (error) {
        console.error('Address transactions error:', error);
        res.status(500).json({ error: 'Failed to get address transactions' });
    }
});

// Get all messages for address
app.get('/address/:address/messages', validateAddress, (req, res) => {
    try {
        const address = req.params.address;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 25;
        const direction = req.query.direction; // 'incoming', 'outgoing', or undefined for both
        
        const messages = blockchain.getMessagesForAddress(address, 1000); // Get large batch
        
        // Filter by direction if specified
        let filteredMessages = messages;
        if (direction === 'incoming') {
            filteredMessages = messages.filter(msg => msg.to === address);
        } else if (direction === 'outgoing') {
            filteredMessages = messages.filter(msg => msg.from === address);
        }
        
        // Sort by timestamp (newest first)
        filteredMessages.sort((a, b) => b.timestamp - a.timestamp);
        
        // Paginate
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const paginatedMessages = filteredMessages.slice(startIndex, endIndex);

        // Don't return encrypted data
        const safeMessages = paginatedMessages.map(msg => ({
            hash: msg.hash,
            from: msg.from,
            to: msg.to,
            timestamp: msg.timestamp,
            messageType: msg.messageType,
            direction: msg.direction,
            blockNumber: msg.blockNumber,
            status: msg.status
        }));

        res.json({
            success: true,
            data: {
                address: address,
                messages: safeMessages,
                pagination: {
                    currentPage: page,
                    totalPages: Math.ceil(filteredMessages.length / limit),
                    totalMessages: filteredMessages.length,
                    hasNextPage: endIndex < filteredMessages.length,
                    hasPrevPage: page > 1
                }
            }
        });
    } catch (error) {
        console.error('Address messages error:', error);
        res.status(500).json({ error: 'Failed to get address messages' });
    }
});

// Get address info
app.get('/address/:address', validateAddress, (req, res) => {
    try {
        const address = req.params.address;
        const accountInfo = blockchain.getAccountInfo(address);
        
        res.json({
            success: true,
            data: accountInfo
        });
    } catch (error) {
        console.error('Address endpoint error:', error);
        res.status(500).json({ error: 'Failed to get address info' });
    }
});

// Get pending transactions
app.get('/transactions/pending', (req, res) => {
    try {
        res.json({
            success: true,
            data: {
                transactions: blockchain.pendingTransactions,
                count: blockchain.pendingTransactions.length
            }
        });
    } catch (error) {
        console.error('Pending transactions error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get pending messages
app.get('/messages/pending', (req, res) => {
    try {
        // Don't return encrypted data
        const safeMessages = blockchain.pendingMessages.map(msg => ({
            hash: msg.hash,
            from: msg.from,
            to: msg.to,
            timestamp: msg.timestamp,
            messageType: msg.messageType,
            status: msg.status
        }));

        res.json({
            success: true,
            data: {
                messages: safeMessages,
                count: blockchain.pendingMessages.length
            }
        });
    } catch (error) {
        console.error('Pending messages error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ========== SECURE WALLET ENDPOINTS ==========

// Create new wallet
app.post('/wallet/create', (req, res) => {
    try {
        console.log('🔑 Creating new secure wallet...');
        
        const privateKey = SecureCrypto.generatePrivateKey();
        const address = SecureCrypto.privateKeyToAddress(privateKey);
        
        // Initialize account in blockchain if it doesn't exist
        if (!blockchain.accounts.has(address)) {
            blockchain.accounts.set(address, {
                balance: '0',
                nonce: 0,
                codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
                storageRoot: '0x0000000000000000000000000000000000000000000000000000000000000000',
                transactionCount: 0,
                messageCount: 0,
                type: 'externally_owned'
            });
            blockchain.saveState();
        }

        console.log(`✅ Secure wallet created: ${address.substring(0, 10)}...`);
        
        res.json({
            success: true,
            data: {
                address: address,
                privateKey: privateKey,
                balance: blockchain.getBalance(address),
                balanceTESAM: blockchain.fromWei(blockchain.getBalance(address)),
                nonce: blockchain.accounts.get(address)?.nonce || 0,
                warning: 'SAVE YOUR PRIVATE KEY SECURELY! It cannot be recovered if lost.',
                securityNotice: 'Never share your private key with anyone!'
            }
        });
    } catch (error) {
        console.error('Wallet creation error:', error);
        res.status(500).json({ error: 'Wallet creation failed' });
    }
});

// Import wallet
app.post('/wallet/import', validatePrivateKey, (req, res) => {
    try {
        const { privateKey } = req.body;
        
        if (!privateKey) {
            return res.status(400).json({ error: 'Private key is required' });
        }

        const address = SecureCrypto.privateKeyToAddress(privateKey);
        
        // Initialize account if it doesn't exist
        if (!blockchain.accounts.has(address)) {
            blockchain.accounts.set(address, {
                balance: '0',
                nonce: 0,
                codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
                storageRoot: '0x0000000000000000000000000000000000000000000000000000000000000000',
                transactionCount: 0,
                messageCount: 0,
                type: 'externally_owned'
            });
            blockchain.saveState();
        }

        console.log(`✅ Wallet imported: ${address.substring(0, 10)}...`);
        
        res.json({
            success: true,
            data: {
                address: address,
                privateKey: privateKey,
                balance: blockchain.getBalance(address),
                balanceTESAM: blockchain.fromWei(blockchain.getBalance(address)),
                nonce: blockchain.accounts.get(address)?.nonce || 0,
                message: 'Wallet successfully imported'
            }
        });
    } catch (error) {
        console.error('Wallet import error:', error);
        res.status(400).json({ error: 'Invalid private key' });
    }
});

// Get wallet info
app.post('/wallet/info', validatePrivateKey, (req, res) => {
    try {
        const { privateKey } = req.body;
        
        if (!privateKey) {
            return res.status(400).json({ error: 'Private key is required' });
        }

        const address = SecureCrypto.privateKeyToAddress(privateKey);
        const accountInfo = blockchain.getAccountInfo(address);
        
        res.json({
            success: true,
            data: accountInfo
        });
    } catch (error) {
        console.error('Wallet info error:', error);
        res.status(500).json({ error: 'Failed to get wallet info' });
    }
});

// Send transaction
app.post('/transaction/send', validatePrivateKey, (req, res) => {
    try {
        const { from, to, amount, privateKey, data } = req.body;
        
        if (!from || !to || !amount || !privateKey) {
            return res.status(400).json({ 
                error: 'From, to, amount, and private key are required' 
            });
        }

        // Validate addresses
        if (!SecureCrypto.validateAddress(from) || !SecureCrypto.validateAddress(to)) {
            return res.status(400).json({ error: 'Invalid address format' });
        }

        // Verify private key matches from address
        const derivedAddress = SecureCrypto.privateKeyToAddress(privateKey);
        if (derivedAddress !== from) {
            return res.status(401).json({ error: 'Private key does not match from address' });
        }

        console.log(`💸 Secure transaction: ${from.substring(0, 10)}... → ${to.substring(0, 10)}...`);
        
        // Convert amount to number and ensure it's handled properly
        const amountNumber = parseFloat(amount);
        if (isNaN(amountNumber) || amountNumber <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        // Create and broadcast transaction
        const transaction = blockchain.createTransaction(from, to, amountNumber, privateKey, data);
        
        // Broadcast to WebSocket clients
        broadcast({
            type: 'new_transaction',
            transaction: { ...transaction, status: 'pending' },
            timestamp: Date.now()
        });
        
        res.json({
            success: true,
            data: {
                transactionHash: transaction.hash,
                from: transaction.from,
                to: transaction.to,
                amount: transaction.amount,
                amountTESAM: blockchain.fromWei(transaction.amount),
                status: 'pending',
                gas: transaction.gas,
                gasPrice: transaction.gasPrice,
                nonce: transaction.nonce
            }
        });
    } catch (error) {
        console.error('Send transaction error:', error);
        res.status(400).json({ error: error.message });
    }
});

// ========== ENCRYPTED MESSAGING ENDPOINTS ==========

// Send encrypted message
app.post('/message/send', validatePrivateKey, (req, res) => {
    try {
        const { from, to, message, privateKey, messageType } = req.body;
        
        if (!from || !to || !message || !privateKey) {
            return res.status(400).json({ 
                error: 'From, to, message, and private key are required' 
            });
        }

        // Validate addresses
        if (!SecureCrypto.validateAddress(from) || !SecureCrypto.validateAddress(to)) {
            return res.status(400).json({ error: 'Invalid address format' });
        }

        // Verify private key matches from address
        const derivedAddress = SecureCrypto.privateKeyToAddress(privateKey);
        if (derivedAddress !== from) {
            return res.status(401).json({ error: 'Private key does not match from address' });
        }

        console.log(`💬 Encrypted message: ${from.substring(0, 10)}... → ${to.substring(0, 10)}...`);
        
        // Send encrypted message
        const messageResult = blockchain.sendEncryptedMessage(
            privateKey, 
            to, 
            message, 
            messageType || 'text'
        );
        
        // Broadcast to WebSocket clients
        broadcast({
            type: 'new_message',
            message: { 
                hash: messageResult.messageHash,
                from: messageResult.from,
                to: messageResult.to,
                timestamp: messageResult.timestamp,
                status: 'pending'
            },
            timestamp: Date.now()
        });
        
        res.json({
            success: true,
            data: {
                messageHash: messageResult.messageHash,
                from: messageResult.from,
                to: messageResult.to,
                timestamp: messageResult.timestamp,
                status: 'pending',
                message: 'Encrypted message sent successfully'
            }
        });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Read encrypted message
app.post('/message/read', validatePrivateKey, (req, res) => {
    try {
        const { messageHash, privateKey } = req.body;
        
        if (!messageHash || !privateKey) {
            return res.status(400).json({ 
                error: 'Message hash and private key are required' 
            });
        }

        // Read and decrypt message
        const decryptedMessage = blockchain.readEncryptedMessage(messageHash, privateKey);
        
        res.json({
            success: true,
            data: decryptedMessage
        });
    } catch (error) {
        console.error('Read message error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Get messages for address
app.post('/messages/list', validatePrivateKey, (req, res) => {
    try {
        const { privateKey, limit, direction } = req.body;
        
        if (!privateKey) {
            return res.status(400).json({ error: 'Private key is required' });
        }

        const address = SecureCrypto.privateKeyToAddress(privateKey);
        const messages = blockchain.getMessagesForAddress(address, limit || 50);
        
        // Filter by direction if specified
        let filteredMessages = messages;
        if (direction === 'incoming') {
            filteredMessages = messages.filter(msg => msg.to === address);
        } else if (direction === 'outgoing') {
            filteredMessages = messages.filter(msg => msg.from === address);
        }
        
        // Don't return encrypted data
        const safeMessages = filteredMessages.map(msg => ({
            hash: msg.hash,
            from: msg.from,
            to: msg.to,
            timestamp: msg.timestamp,
            messageType: msg.messageType,
            direction: msg.direction,
            blockNumber: msg.blockNumber,
            status: msg.status
        }));

        res.json({
            success: true,
            data: {
                address: address,
                messages: safeMessages,
                total: filteredMessages.length
            }
        });
    } catch (error) {
        console.error('List messages error:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

// ========== BLOCK GENERATION ENDPOINTS ==========

// Generate block
app.post('/block/generate', (req, res) => {
    try {
        const { minerAddress } = req.body;
        
        if (!minerAddress) {
            return res.status(400).json({ error: 'Miner address is required' });
        }

        if (!SecureCrypto.validateAddress(minerAddress)) {
            return res.status(400).json({ error: 'Invalid miner address' });
        }

        console.log(`⛏️ Block generation request from: ${minerAddress.substring(0, 10)}...`);
        
        const block = blockchain.generateBlock(minerAddress);
        
        // Broadcast new block
        broadcast({
            type: 'new_block',
            block: {
                number: block.number,
                hash: block.hash,
                transactions: block.transactions.length,
                messages: block.messages.length,
                miner: block.miner,
                timestamp: block.timestamp
            },
            timestamp: Date.now()
        });
        
        res.json({
            success: true,
            data: {
                blockNumber: block.number,
                blockHash: block.hash,
                transactions: block.transactions.length,
                messages: block.messages.length,
                miner: block.miner,
                reward: blockchain.miningReward + ' TESAM'
            }
        });
    } catch (error) {
        console.error('Block generation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ========== TOKEN ENDPOINTS ==========

// Get tokens list
app.get('/tokens', (req, res) => {
    try {
        // Return TESAM as the only token
        const tokens = {
            '0x0000000000000000000000000000000000000000': {
                name: 'Tesam Token',
                symbol: 'TESAM',
                totalSupply: blockchain.getBlockchainInfo().totalSupply,
                decimals: 18,
                holderCount: blockchain.accounts.size
            }
        };
        
        res.json({
            success: true,
            tokens: tokens
        });
    } catch (error) {
        console.error('Tokens endpoint error:', error);
        res.status(500).json({ error: 'Failed to get tokens' });
    }
});

// Get token details
app.get('/token/:address', (req, res) => {
    try {
        const tokenAddress = req.params.address;
        
        // Currently only support TESAM token
        if (tokenAddress === '0x0000000000000000000000000000000000000000') {
            const holders = Array.from(blockchain.accounts.entries())
                .filter(([address, account]) => parseInt(account.balance) > 0)
                .map(([address, account]) => ({
                    address,
                    balance: blockchain.fromWei(account.balance),
                    percentage: (parseInt(account.balance) / parseInt(blockchain.getBlockchainInfo().totalSupply)) * 100
                }))
                .sort((a, b) => parseFloat(b.balance) - parseFloat(a.balance));
            
            res.json({
                address: tokenAddress,
                name: 'Tesam Token',
                symbol: 'TESAM',
                totalSupply: blockchain.getBlockchainInfo().totalSupply,
                totalSupplyTESAM: blockchain.getBlockchainInfo().totalSupplyTESAM,
                decimals: 18,
                totalHolders: holders.length,
                holders: holders.slice(0, 10) // Top 10 holders
            });
        } else {
            res.status(404).json({ error: 'Token not found' });
        }
    } catch (error) {
        console.error('Token endpoint error:', error);
        res.status(500).json({ error: 'Failed to get token details' });
    }
});

// ========== SECURE DEBUG ENDPOINTS ==========

// Mine initial supply (secured endpoint)
app.post('/debug/mine-initial-supply', async (req, res) => {
    try {
        // Additional security check for this sensitive operation
        const authToken = req.headers['x-debug-auth'];
        const validToken = process.env.DEBUG_AUTH_TOKEN || 'secure-debug-token-98451';
        
        if (authToken !== validToken) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { targetAddress, amount } = req.body;
        
        if (!targetAddress) {
            return res.status(400).json({ error: 'Target address is required' });
        }

        if (!SecureCrypto.validateAddress(targetAddress)) {
            return res.status(400).json({ error: 'Invalid target address' });
        }

        const mineAmount = amount || 200000000;
        
        console.log(`\n🎯 TESAM SUPPLY MINING INITIATED`);
        console.log(`📍 Target: ${targetAddress}`);
        console.log(`⛏️ Amount: ${mineAmount.toLocaleString()} TESAM\n`);
        
        const finalBalance = await blockchain.mineInitialSupply(targetAddress, mineAmount);
        
        res.json({
            success: true,
            data: {
                message: 'TESAM supply mining completed successfully',
                targetAddress: targetAddress,
                totalMined: `${mineAmount.toLocaleString()} TESAM`,
                finalBalance: {
                    wei: finalBalance,
                    tesam: blockchain.fromWei(finalBalance)
                },
                blocksGenerated: blockchain.chain.length,
                securityNotice: 'Funds have been securely generated to the specified address'
            }
        });
    } catch (error) {
        console.error('Supply mining error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get blockchain state (debug)
app.get('/debug/state', (req, res) => {
    try {
        const info = blockchain.getBlockchainInfo();
        
        res.json({
            success: true,
            data: {
                ...info,
                accounts: Array.from(blockchain.accounts.entries()).map(([address, account]) => ({
                    address,
                    balance: blockchain.fromWei(account.balance) + ' TESAM',
                    nonce: account.nonce,
                    transactionCount: account.transactionCount,
                    messageCount: account.messageCount
                })),
                isValid: blockchain.isValidChain()
            }
        });
    } catch (error) {
        console.error('Debug state error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Serve main pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'explorer.html'));
});

app.get('/wallet', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/messaging', (req, res) => {
    res.sendFile(path.join(__dirname, 'messaging.html'));
});

// ========== WEBSOCKET SECURE COMMUNICATION ==========

const connectedClients = new Set();

wss.on('connection', (ws, req) => {
    const clientId = crypto.randomBytes(8).toString('hex');
    const clientIp = req.socket.remoteAddress;
    
    connectedClients.add(ws);
    
    console.log(`🔌 New secure WebSocket connection: ${clientId} from ${clientIp}`);
    
    // Send welcome message
    ws.send(JSON.stringify({
        type: 'welcome',
        clientId: clientId,
        message: 'Connected to TESAM Secure Blockchain with Encrypted Messaging',
        networkId: 98451,
        chainId: blockchain.chainId,
        timestamp: Date.now()
    }));

    // Send initial blockchain state
    ws.send(JSON.stringify({
        type: 'blockchain_state',
        stats: blockchain.getBlockchainInfo(),
        bestBlock: blockchain.getLatestBlock(),
        timestamp: Date.now()
    }));

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            // Validate message structure
            if (!data.type || typeof data.type !== 'string') {
                ws.send(JSON.stringify({
                    type: 'error',
                    message: 'Invalid message format'
                }));
                return;
            }

            switch (data.type) {
                case 'ping':
                    ws.send(JSON.stringify({ 
                        type: 'pong', 
                        timestamp: Date.now() 
                    }));
                    break;
                    
                case 'subscribe_blocks':
                    ws.subscribeBlocks = true;
                    ws.send(JSON.stringify({
                        type: 'subscribed',
                        subscription: 'blocks'
                    }));
                    break;
                    
                case 'subscribe_transactions':
                    ws.subscribeTransactions = true;
                    ws.send(JSON.stringify({
                        type: 'subscribed',
                        subscription: 'transactions'
                    }));
                    break;
                    
                case 'subscribe_messages':
                    ws.subscribeMessages = true;
                    ws.send(JSON.stringify({
                        type: 'subscribed',
                        subscription: 'messages'
                    }));
                    break;
                    
                default:
                    ws.send(JSON.stringify({
                        type: 'error',
                        message: 'Unknown message type'
                    }));
            }
        } catch (error) {
            console.error('WebSocket message error:', error);
            ws.send(JSON.stringify({
                type: 'error',
                message: 'Invalid message format'
            }));
        }
    });

    ws.on('close', () => {
        connectedClients.delete(ws);
        console.log(`🔌 WebSocket connection closed: ${clientId}`);
    });

    ws.on('error', (error) => {
        console.error(`❌ WebSocket error for ${clientId}:`, error);
        connectedClients.delete(ws);
    });
});

function broadcast(message) {
    const messageStr = JSON.stringify({
        ...message,
        timestamp: Date.now()
    });
    
    let sentCount = 0;
    connectedClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            // Apply subscription filters
            if (message.type === 'new_block' && client.subscribeBlocks) {
                client.send(messageStr);
                sentCount++;
            } else if (message.type === 'new_transaction' && client.subscribeTransactions) {
                client.send(messageStr);
                sentCount++;
            } else if (message.type === 'new_message' && client.subscribeMessages) {
                client.send(messageStr);
                sentCount++;
            } else if (message.type === 'blockchain_state') {
                client.send(messageStr);
                sentCount++;
            }
        }
    });
    
    if (sentCount > 0) {
        console.log(`📢 Broadcasted ${message.type} to ${sentCount} clients`);
    }
}

// Periodic stats broadcast
setInterval(() => {
    broadcast({
        type: 'blockchain_state',
        stats: blockchain.getBlockchainInfo(),
        bestBlock: blockchain.getLatestBlock()
    });
}, 30000); // Every 30 seconds

// Auto-block generation based on activity
setInterval(() => {
    if (blockchain.shouldGenerateBlock()) {
        console.log('🤖 Auto-generating block due to network activity...');
        try {
            // Use the first account with balance as miner
            const minerAddress = Array.from(blockchain.accounts.entries())
                .find(([address, account]) => parseInt(account.balance) > 0)?.[0];
            
            if (minerAddress) {
                blockchain.generateBlock(minerAddress);
            }
        } catch (error) {
            console.error('Auto-block generation failed:', error.message);
        }
    }
}, 10000); // Check every 10 seconds

// ========== ERROR HANDLING ==========

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        path: req.path,
        method: req.method
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('🚨 Global error handler:', error);
    
    // Don't leak error details in production
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ 
            error: 'Internal server error' 
        });
    } else {
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message,
            stack: error.stack
        });
    }
});

// Unhandled rejection handler
process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    console.error('🚨 Uncaught Exception:', error);
    // Save state and exit gracefully
    blockchain.saveState();
    process.exit(1);
});

// ========== SERVER STARTUP ==========

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Auto-save interval
const AUTO_SAVE_INTERVAL = 30000; // 30 seconds
setInterval(() => {
    console.log('💾 Auto-saving secure blockchain state...');
    blockchain.saveState();
}, AUTO_SAVE_INTERVAL);

server.listen(PORT, HOST, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════════╗
║                   TESAM SECURE BLOCKCHAIN v3.0                   ║
╠══════════════════════════════════════════════════════════════════╣
║ 🚀 REVOLUTIONARY FEATURES:                                      ║
║   ✅ Encrypted Wallet-to-Wallet Messaging                       ║
║   ✅ Message-Based Consensus (No PoW/PoS)                       ║
║   ✅ Secure Transactions with Military-Grade Encryption         ║
║   ✅ Auto-Block Generation Based on Network Activity            ║
║   ✅ Real Social Media Integration on Blockchain                ║
║                                                                  ║
║ 🔒 SECURITY FEATURES:                                            ║
║   ✅ AES-256-GCM Encrypted Messages                             ║
║   ✅ Secure Private Key Management                               ║
║   ✅ Encrypted Blockchain Storage                               ║
║   ✅ Rate Limiting & DDoS Protection                            ║
║   ✅ Input Validation & Sanitization                            ║
║                                                                  ║
║ 🌐 NETWORK INFORMATION:                                          ║
║   📡 API Server: http://${HOST}:${PORT}                          ║
║   🔌 WebSocket: ws://${HOST}:${PORT}                            ║
║   ⛓️  Chain ID: ${blockchain.chainId}                                     ║
║   💰 Mining Reward: ${blockchain.miningReward} TESAM                      ║
║   🔑 Genesis Block: ${blockchain.chain[0]?.hash.substring(0, 16)}...      ║
║   💬 Consensus: Message-Based Activity                          ║
║                                                                  ║
║ 📊 EXPLORER ENDPOINTS:                                           ║
║   GET  /stats - Blockchain statistics                           ║
║   GET  /chain - Blocks with pagination                          ║
║   GET  /search/:query - Search blockchain                       ║
║   GET  /block/:number - Block details                           ║
║   GET  /transaction/:hash - Transaction details                 ║
║   GET  /message/:hash - Message details                         ║
║   GET  /address/:address - Address details                      ║
║                                                                  ║
║ 👛 WALLET ENDPOINTS:                                             ║
║   POST /wallet/create - Create new wallet                       ║
║   POST /wallet/import - Import wallet                           ║
║   POST /wallet/info - Get wallet info                           ║
║   POST /transaction/send - Send transaction                     ║
║                                                                  ║
║ 💬 MESSAGING ENDPOINTS:                                          ║
║   POST /message/send - Send encrypted message                   ║
║   POST /message/read - Read encrypted message                   ║
║   POST /messages/list - List messages                           ║
║   GET  /address/:address/messages - Get address messages        ║
║                                                                  ║
║ ⚠️  WARNING: This is a revolutionary blockchain with            ║
║     encrypted social media capabilities. Handle with care!      ║
╚══════════════════════════════════════════════════════════════════╝
    `);
    
    const founderAddress = Array.from(blockchain.accounts.keys())[0];
    const founderBalance = blockchain.getBalance(founderAddress);
    
    console.log(`\n📊 Initial Blockchain State:`);
    console.log(`   Blocks: ${blockchain.chain.length}`);
    console.log(`   Accounts: ${blockchain.accounts.size}`);
    console.log(`   Messages: ${blockchain.messageHistory.size}`);
    console.log(`   Transactions: ${blockchain.transactionHistory.size}`);
    console.log(`   Founder Balance: ${blockchain.fromWei(founderBalance)} TESAM`);
    console.log(`   Pending Transactions: ${blockchain.pendingTransactions.length}`);
    console.log(`   Pending Messages: ${blockchain.pendingMessages.length}`);
    console.log(`   Chain Valid: ${blockchain.isValidChain() ? '✅' : '❌'}`);
    console.log(`\n🚀 TESAM Secure Blockchain with Encrypted Messaging is running!\n`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT. Performing graceful shutdown...');
    
    console.log('💾 Saving final blockchain state...');
    blockchain.saveState();
    
    console.log('🔌 Closing WebSocket connections...');
    wss.close();
    
    console.log('🌐 Closing HTTP server...');
    server.close(() => {
        console.log('✅ Server shut down gracefully');
        process.exit(0);
    });
    
    // Force shutdown after 10 seconds
    setTimeout(() => {
        console.log('⚠️ Forcing shutdown after timeout');
        process.exit(1);
    }, 10000);
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM. Shutting down...');
    blockchain.saveState();
    server.close(() => {
        process.exit(0);
    });
});