
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const archiver = require('archiver');

const DB_PATH = path.join(__dirname, 'database');
const BACKUP_PATH = path.join(__dirname, 'backups');

async function createBackup() {
    try {

        await fs.mkdir(BACKUP_PATH, { recursive: true });
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = path.join(BACKUP_PATH, `backup-${timestamp}.zip`);
        
        const output = fs.createWriteStream(backupFile);
        const archive = archiver('zip', { zlib: { level: 9 } });
        
        return new Promise((resolve, reject) => {
            output.on('close', () => {
                console.log(`Backup criado: ${backupFile}`);
                console.log(`Tamanho: ${(archive.pointer() / 1024 / 1024).toFixed(2)} MB`);
                resolve(backupFile);
            });
            
            archive.on('error', (err) => {
                reject(err);
            });
            
            archive.pipe(output);
            archive.directory(DB_PATH, 'database');
            archive.finalize();
        });
        
    } catch (error) {
        console.error('Erro ao criar backup:', error);
        throw error;
    }
}

async function cleanupOldBackups(maxBackups = 10) {
    try {
        const files = await fs.readdir(BACKUP_PATH);
        const backupFiles = files.filter(f => f.startsWith('backup-') && f.endsWith('.zip'));
        
        if (backupFiles.length > maxBackups) {
            backupFiles.sort();
            const filesToDelete = backupFiles.slice(0, backupFiles.length - maxBackups);
            
            for (const file of filesToDelete) {
                await fs.unlink(path.join(BACKUP_PATH, file));
                console.log(`Backup antigo removido: ${file}`);
            }
        }
    } catch (error) {
        console.error('Erro ao limpar backups antigos:', error);
    }
}

async function main() {
    console.log('Iniciando backup automático...');
    
    try {
        await createBackup();
        await cleanupOldBackups();
        
        console.log('Backup concluído com sucesso!');
    } catch (error) {
        console.error('Falha no backup:', error);
        process.exit(1);
    }
}


if (require.main === module) {
    main();
}

module.exports = { createBackup, cleanupOldBackups };