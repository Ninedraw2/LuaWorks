const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const archiver = require('archiver');
const crypto = require('crypto');
const cryptoRandomString = require('crypto-random-string');

const DB_PATH = path.join(__dirname, 'database');
const BACKUP_PATH = path.join(__dirname, 'backups');
const ENCRYPTION_KEY = process.env.BACKUP_ENCRYPTION_KEY || cryptoRandomString({length: 64, type: 'base64'});

function validatePath(filePath) {
    const normalized = path.normalize(filePath);
    if (normalized.includes('..')) {
        throw new Error('Caminho inválido detectado');
    }
    return normalized;
}

async function encryptBackup(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', crypto.createHash('sha256').update(key).digest(), iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return {
        iv: iv.toString('hex'),
        data: encrypted,
        authTag: authTag.toString('hex')
    };
}

async function createSecureBackup() {
    try {
        await fs.mkdir(BACKUP_PATH, { recursive: true });
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = path.join(BACKUP_PATH, `backup-${timestamp}.lwbak`);
        
        const output = fs.createWriteStream(backupFile);
        const archive = archiver('zip', { 
            zlib: { level: 9 },
            statConcurrency: 1
        });
        
        return new Promise((resolve, reject) => {
            output.on('close', async () => {
                try {
                    const backupData = await fs.readFile(backupFile);
                    
                    const encrypted = await encryptBackup(backupData.toString('base64'), ENCRYPTION_KEY);
                    
                    const finalBackup = {
                        version: '2.0',
                        timestamp: timestamp,
                        encryptedData: encrypted.data,
                        iv: encrypted.iv,
                        authTag: encrypted.authTag,
                        hash: crypto.createHash('sha256').update(backupData).digest('hex')
                    };
                    
                    await fs.writeFile(backupFile, JSON.stringify(finalBackup, null, 2));
                    
                    await fs.writeFile(
                        path.join(BACKUP_PATH, `backup-${timestamp}.info`),
                        `Backup criado: ${timestamp}\nHash: ${finalBackup.hash}\nTamanho: ${(archive.pointer() / 1024 / 1024).toFixed(2)} MB`
                    );
                    
                    console.log(`Backup seguro criado: ${backupFile}`);
                    resolve(backupFile);
                    
                } catch (error) {
                    reject(error);
                }
            });
            
            archive.on('error', (err) => {
                reject(err);
            });
            
            archive.pipe(output);
            
            fs.readdir(DB_PATH).then(dbFiles => {
                Promise.all(dbFiles.map(async (file) => {
                    const filePath = path.join(DB_PATH, file);
                    const stats = await fs.stat(filePath);
                    if (stats.isFile() && file.endsWith('.json')) {
                        const safePath = validatePath(filePath);
                        archive.file(safePath, { name: path.join('database', file) });
                    }
                })).then(() => {
                    archive.finalize();
                }).catch(reject);
            }).catch(reject);
        });
        
    } catch (error) {
        throw error;
    }
}

async function verifyBackupIntegrity(backupFile) {
    try {
        const data = await fs.readFile(backupFile, 'utf8');
        const backup = JSON.parse(data);
        
        if (!backup.version || !backup.encryptedData || !backup.iv || !backup.authTag || !backup.hash) {
            throw new Error('Formato de backup inválido');
        }
        
        return {
            valid: true,
            timestamp: backup.timestamp,
            hash: backup.hash,
            size: (await fs.stat(backupFile)).size
        };
    } catch (error) {
        return {
            valid: false,
            error: error.message
        };
    }
}

async function cleanupOldBackups(maxBackups = 10) {
    try {
        const files = await fs.readdir(BACKUP_PATH);
        const backupFiles = files.filter(f => f.startsWith('backup-') && f.endsWith('.lwbak'));
        
        if (backupFiles.length > maxBackups) {
            const backupInfos = await Promise.all(
                backupFiles.map(async (file) => {
                    const filePath = path.join(BACKUP_PATH, file);
                    const stats = await fs.stat(filePath);
                    return {
                        file,
                        path: filePath,
                        created: stats.birthtime
                    };
                })
            );
            
            backupInfos.sort((a, b) => a.created - b.created);
            
            const filesToDelete = backupInfos.slice(0, backupInfos.length - maxBackups);
            
            for (const backup of filesToDelete) {
                await fs.unlink(backup.path);
                
                const infoFile = backup.path.replace('.lwbak', '.info');
                try {
                    await fs.unlink(infoFile);
                } catch (error) {
                }
                
                console.log(`Backup antigo removido: ${backup.file}`);
            }
        }
    } catch (error) {
    }
}

async function main() {
    try {
        await createSecureBackup();
        
        const backupFiles = await fs.readdir(BACKUP_PATH);
        const latestBackup = backupFiles
            .filter(f => f.endsWith('.lwbak'))
            .sort()
            .pop();
        
        if (latestBackup) {
            const verification = await verifyBackupIntegrity(path.join(BACKUP_PATH, latestBackup));
            if (verification.valid) {
                console.log(`Backup verificado: ${latestBackup}`);
                console.log(`Hash: ${verification.hash}`);
            } else {
                console.error(`Backup corrompido: ${verification.error}`);
            }
        }
        
        await cleanupOldBackups();
        
    } catch (error) {
        console.error('Erro no backup:', error);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { createSecureBackup, verifyBackupIntegrity, cleanupOldBackups };