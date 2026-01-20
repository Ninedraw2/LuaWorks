// server.js
const express = require('express');
const fetch = require('node-fetch');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;

// URL do seu site que você quer manter ativo
const TARGET_URL = process.env.TARGET_URL || 'https://luaworks.onrender.com';

// Função para fazer ping
async function pingSite() {
    try {
        const response = await fetch(TARGET_URL);
        console.log(`[${new Date().toISOString()}] Ping realizado com status: ${response.status}`);
        return true;
    } catch (error) {
        console.error(`[${new Date().toISOString()}] Erro no ping: ${error.message}`);
        return false;
    }
}

// Agendar ping a cada 1 minuto
cron.schedule('*/1 * * * *', async () => {
    console.log(`[${new Date().toISOString()}] Executando ping automático...`);
    await pingSite();
});

// Rota principal
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'auto-ping',
        target: TARGET_URL,
        interval: '1 minuto',
        lastPing: new Date().toISOString()
    });
});

// Rota para ping manual
app.get('/ping', async (req, res) => {
    const success = await pingSite();
    res.json({ 
        success, 
        message: success ? 'Ping realizado com sucesso' : 'Falha no ping',
        timestamp: new Date().toISOString()
    });
});

// Rota de saúde
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`Servidor de ping rodando na porta ${PORT}`);
    console.log(`Monitorando: ${TARGET_URL}`);
    
    // Executar ping inicial
    pingSite();
});