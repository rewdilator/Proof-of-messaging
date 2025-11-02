// messager/block-monitor.js - TESAM Block Generation Monitor
const { TesamBlockchain, SecureCrypto } = require('./advanced-chain');

class BlockMonitor {
    constructor() {
        this.blockchain = new TesamBlockchain();
        this.autoGenerate = true;
        this.minTransactions = 3;
        this.minMessages = 2;
        this.checkInterval = 10000; // Check every 10 seconds
        
        this.startMonitoring();
    }
    
    startMonitoring() {
        console.log('🔍 Starting TESAM Block Generation Monitor...');
        
        setInterval(() => {
            this.checkBlockGeneration();
        }, this.checkInterval);
    }
    
    checkBlockGeneration() {
        const stats = this.blockchain.getBlockchainInfo();
        const shouldGenerate = this.blockchain.shouldGenerateBlock();
        
        console.log(`📊 Monitor: ${stats.pendingTransactions} pending tx, ${stats.pendingMessages} pending messages`);
        
        if (shouldGenerate && this.autoGenerate) {
            this.generateBlock();
        }
    }
    
    generateBlock() {
        try {
            // Find an account with balance to use as miner
            const miner = Array.from(this.blockchain.accounts.entries())
                .find(([address, account]) => parseInt(account.balance) > 0);
            
            if (miner) {
                const [minerAddress] = miner;
                console.log(`⛏️ Auto-generating block with miner: ${minerAddress.substring(0, 10)}...`);
                
                const block = this.blockchain.generateBlock(minerAddress);
                
                console.log(`✅ Block #${block.number} generated successfully!`);
                console.log(`   Transactions: ${block.transactions.length}`);
                console.log(`   Messages: ${block.messages.length}`);
                console.log(`   Miner reward: ${this.blockchain.miningReward} TESAM`);
            } else {
                console.log('⚠️ No suitable miner found for block generation');
            }
        } catch (error) {
            console.error('❌ Block generation failed:', error.message);
        }
    }
    
    // Manual block generation
    manualGenerate(minerAddress) {
        if (!SecureCrypto.validateAddress(minerAddress)) {
            throw new Error('Invalid miner address');
        }
        
        return this.blockchain.generateBlock(minerAddress);
    }
    
    // Get generation statistics
    getStats() {
        const blockchainInfo = this.blockchain.getBlockchainInfo();
        
        return {
            autoGenerate: this.autoGenerate,
            checkInterval: this.checkInterval,
            pendingTransactions: blockchainInfo.pendingTransactions,
            pendingMessages: blockchainInfo.pendingMessages,
            shouldGenerate: this.blockchain.shouldGenerateBlock(),
            lastBlock: this.blockchain.getLatestBlock(),
            totalBlocks: blockchainInfo.blockHeight,
            totalTransactions: blockchainInfo.totalTransactions,
            totalMessages: blockchainInfo.totalMessages
        };
    }
}

// Export for use in other modules
module.exports = BlockMonitor;

// Start monitor if run directly
if (require.main === module) {
    const monitor = new BlockMonitor();
    
    // CLI interface for manual control
    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    console.log('\n🚀 TESAM Block Generation Monitor Started!');
    console.log('Commands:');
    console.log('  stats - Show current statistics');
    console.log('  generate [address] - Manually generate block');
    console.log('  auto on/off - Toggle auto-generation');
    console.log('  exit - Stop monitor\n');
    
    rl.on('line', (input) => {
        const [command, ...args] = input.trim().split(' ');
        
        switch (command) {
            case 'stats':
                const stats = monitor.getStats();
                console.log('\n📊 Block Generation Statistics:');
                console.log(`   Auto-generation: ${stats.autoGenerate ? 'ON' : 'OFF'}`);
                console.log(`   Pending transactions: ${stats.pendingTransactions}`);
                console.log(`   Pending messages: ${stats.pendingMessages}`);
                console.log(`   Should generate: ${stats.shouldGenerate ? 'YES' : 'NO'}`);
                console.log(`   Total blocks: ${stats.totalBlocks}`);
                console.log(`   Last block: #${stats.lastBlock?.number || 0}`);
                break;
                
            case 'generate':
                const address = args[0];
                if (address && SecureCrypto.validateAddress(address)) {
                    try {
                        const block = monitor.manualGenerate(address);
                        console.log(`✅ Manual block #${block.number} generated!`);
                    } catch (error) {
                        console.log('❌ Generation failed:', error.message);
                    }
                } else {
                    console.log('❌ Please provide a valid address');
                }
                break;
                
            case 'auto':
                if (args[0] === 'on') {
                    monitor.autoGenerate = true;
                    console.log('✅ Auto-generation enabled');
                } else if (args[0] === 'off') {
                    monitor.autoGenerate = false;
                    console.log('❌ Auto-generation disabled');
                } else {
                    console.log('❌ Usage: auto on/off');
                }
                break;
                
            case 'exit':
                console.log('👋 Stopping monitor...');
                rl.close();
                process.exit(0);
                break;
                
            default:
                console.log('❌ Unknown command');
        }
    });
}