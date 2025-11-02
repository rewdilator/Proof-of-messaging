// backup-data.js
const BlockchainPersistence = require('./blockchain-persistence');
const fs = require('fs');
const path = require('path');

function createBackup() {
    const persistence = new BlockchainPersistence();
    const backupDir = path.join(__dirname, 'backups');
    
    if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
    }
    
    const backupFile = path.join(backupDir, `blockchain-backup-${Date.now()}.json`);
    
    try {
        const blockchainFile = path.join(persistence.dataDir, 'blockchain.json');
        if (fs.existsSync(blockchainFile)) {
            fs.copyFileSync(blockchainFile, backupFile);
            console.log(`✅ Backup created: ${backupFile}`);
        } else {
            console.log('❌ No blockchain data to backup');
        }
    } catch (error) {
        console.error('❌ Backup failed:', error);
    }
}

// Create backup if run directly
if (require.main === module) {
    createBackup();
}

module.exports = { createBackup };