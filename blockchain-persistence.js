// blockchain-persistence.js
const fs = require('fs');
const path = require('path');

class BlockchainPersistence {
    constructor() {
        this.dataDir = path.join(__dirname, 'data');
        this.blockchainFile = path.join(this.dataDir, 'blockchain.json');
        this.ensureDataDirectory();
    }

    ensureDataDirectory() {
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }
    }

    saveBlockchain(blockchain) {
        try {
            // Convert BigInt values to strings for JSON serialization
            const serializableBlockchain = {
                chain: blockchain.chain.map(block => this.serializeBlock(block)),
                pendingTransactions: blockchain.pendingTransactions.map(tx => this.serializeTransaction(tx)),
                accounts: Array.from(blockchain.accounts.entries()).map(([address, account]) => ({
                    address,
                    balance: account.balance.toString(),
                    nonce: account.nonce,
                    transactionCount: account.transactionCount || 0
                })),
                tokens: Array.from(blockchain.tokens.entries()).map(([address, token]) => ({
                    address,
                    name: token.name,
                    symbol: token.symbol,
                    totalSupply: token.totalSupply.toString(),
                    decimals: token.decimals,
                    owner: token.owner,
                    balances: Array.from(token.balances.entries()).map(([addr, balance]) => ({
                        address: addr,
                        balance: balance.toString()
                    })),
                    transactions: token.transactions || 0
                })),
                transactionHistory: Array.from(blockchain.transactionHistory.entries()).map(([hash, tx]) => ({
                    hash,
                    ...this.serializeTransaction(tx)
                })),
                difficulty: blockchain.difficulty,
                miningReward: blockchain.miningReward,
                gasPrice: blockchain.gasPrice
            };

            fs.writeFileSync(this.blockchainFile, JSON.stringify(serializableBlockchain, null, 2));
            console.log('💾 Blockchain state saved successfully');
            return true;
        } catch (error) {
            console.error('❌ Error saving blockchain:', error);
            return false;
        }
    }

    loadBlockchain() {
        try {
            if (!fs.existsSync(this.blockchainFile)) {
                console.log('📁 No saved blockchain found, starting fresh');
                return null;
            }

            const data = JSON.parse(fs.readFileSync(this.blockchainFile, 'utf8'));
            console.log('📂 Loaded blockchain from disk');

            return {
                chain: data.chain.map(block => this.deserializeBlock(block)),
                pendingTransactions: data.pendingTransactions.map(tx => this.deserializeTransaction(tx)),
                accounts: new Map(data.accounts.map(acc => [acc.address, {
                    balance: acc.balance,
                    nonce: acc.nonce,
                    transactionCount: acc.transactionCount || 0,
                    codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
                    storageRoot: '0x0000000000000000000000000000000000000000000000000000000000000000'
                }])),
                tokens: new Map(data.tokens.map(token => [token.address, {
                    address: token.address,
                    name: token.name,
                    symbol: token.symbol,
                    totalSupply: token.totalSupply,
                    decimals: token.decimals,
                    owner: token.owner,
                    balances: new Map(token.balances.map(b => [b.address, b.balance])),
                    allowances: new Map(),
                    transactions: token.transactions || 0,
                    type: 'ERC20'
                }])),
                transactionHistory: new Map(data.transactionHistory.map(item => [item.hash, this.deserializeTransaction(item)])),
                difficulty: data.difficulty,
                miningReward: data.miningReward,
                gasPrice: data.gasPrice
            };
        } catch (error) {
            console.error('❌ Error loading blockchain:', error);
            return null;
        }
    }

    serializeBlock(block) {
        return {
            ...block,
            transactions: block.transactions.map(tx => this.serializeTransaction(tx)),
            blockReward: block.blockReward.toString()
        };
    }

    deserializeBlock(block) {
        return {
            ...block,
            transactions: block.transactions.map(tx => this.deserializeTransaction(tx)),
            blockReward: block.blockReward
        };
    }

    serializeTransaction(transaction) {
        const serialized = { ...transaction };
        // Convert BigInt values to strings
        if (typeof serialized.amount === 'bigint') {
            serialized.amount = serialized.amount.toString();
        }
        if (serialized.value && typeof serialized.value === 'bigint') {
            serialized.value = serialized.value.toString();
        }
        return serialized;
    }

    deserializeTransaction(transaction) {
        const deserialized = { ...transaction };
        // Convert string values back to BigInt where needed
        if (typeof deserialized.amount === 'string') {
            deserialized.amount = deserialized.amount;
        }
        if (deserialized.value && typeof deserialized.value === 'string') {
            deserialized.value = deserialized.value;
        }
        return deserialized;
    }
}

module.exports = BlockchainPersistence;