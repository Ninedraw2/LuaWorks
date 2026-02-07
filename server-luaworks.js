const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || '66e2860d1de0f99a235edff69876c8db6db1e946997bf9196905d83ba6ae518fe8ddfc2646b2164848d36146275e586eb018a211165bf3f079baa1a6b799fd04';

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'FisherMAN1909';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'N10Sz!@,;>';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'laila.cypher19@proton.me';

const DB_PATH = path.join(__dirname, 'database');
const UPLOADS_PATH = path.join(__dirname, 'uploads');
const PUBLIC_PATH = path.join(__dirname, 'public');

// Inicializar Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
if (!supabaseUrl || !supabaseKey) {
    console.error('SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY são obrigatórios no .env');
    process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseKey);

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_PATH);
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const random = Math.random().toString(36).substring(2, 8);
        const originalName = path.parse(file.originalname).name;
        const extension = path.extname(file.originalname);
        const uniqueName = `${originalName}_${timestamp}_${random}${extension}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.js', '.json', '.py', '.xml', '.html', '.css', '.md', '.lua'];
        const extname = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(extname)) {
            cb(null, true);
        } else {
            cb(new Error(`Tipo de arquivo não permitido. Formatos: ${allowedTypes.join(', ')}`));
        }
    }
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_PATH));
app.use('/uploads', express.static(UPLOADS_PATH));

// ============================================
// FUNÇÕES DE BANCO DE DADOS SUPABASE
// ============================================

/**
 * Lê dados de uma tabela do Supabase (substitui readDatabase)
 * @param {string} table - Nome da tabela
 * @param {Object} options - Opções de query
 * @returns {Promise<any>} - Dados da tabela
 */
async function readFromSupabase(table, options = {}) {
    try {
        const { filters = {}, order = {}, limit, single = false } = options;
        
        let query = supabase.from(table).select('*');
        
        // Aplicar filtros
        Object.entries(filters).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
                query = query.eq(key, value);
            }
        });
        
        // Aplicar ordenação
        if (order.column && order.direction) {
            query = query.order(order.column, { ascending: order.direction === 'asc' });
        }
        
        // Aplicar limite
        if (limit) {
            query = query.limit(limit);
        }
        
        const { data, error } = await query;
        
        if (error) throw error;
        
        return single ? (data[0] || null) : data;
        
    } catch (error) {
        console.error(`Erro ao ler da tabela ${table}:`, error);
        
        // Retornar valores padrão para compatibilidade
        if (table === 'users') return { users: [] };
        if (table === 'products') return [];
        if (table === 'orders') return { orders: [] };
        if (table === 'stats') return generateDefaultStats();
        if (table === 'downloads') return { downloads: [] };
        if (table === 'reviews') return { reviews: [] };
        if (table === 'logs') return { logs: [] };
        return single ? null : [];
    }
}

/**
 * Escreve dados em uma tabela do Supabase (substitui writeDatabase)
 * @param {string} table - Nome da tabela
 * @param {Object|Array} data - Dados para inserir/atualizar
 * @param {string} operation - 'insert' ou 'update'
 * @param {Object} conditions - Condições para update
 * @returns {Promise<any>} - Resultado da operação
 */
async function writeToSupabase(table, data, operation = 'insert', conditions = {}) {
    try {
        let result;
        
        if (operation === 'insert') {
            const { data: inserted, error } = await supabase
                .from(table)
                .insert(Array.isArray(data) ? data : [data])
                .select();
                
            if (error) throw error;
            result = inserted;
            
        } else if (operation === 'update') {
            let query = supabase.from(table).update(data);
            
            // Aplicar condições
            Object.entries(conditions).forEach(([key, value]) => {
                query = query.eq(key, value);
            });
            
            const { data: updated, error } = await query.select();
            if (error) throw error;
            result = updated;
            
        } else if (operation === 'delete') {
            let query = supabase.from(table).delete();
            
            Object.entries(conditions).forEach(([key, value]) => {
                query = query.eq(key, value);
            });
            
            const { error } = await query;
            if (error) throw error;
            result = { success: true };
        }
        
        return result;
        
    } catch (error) {
        console.error(`Erro na operação ${operation} na tabela ${table}:`, error);
        throw error;
    }
}

/**
 * Gera estatísticas padrão
 * @returns {Object} - Estatísticas padrão
 */
function generateDefaultStats() {
    return {
        totalUsers: 0,
        activeUsers: 0,
        totalOrders: 0,
        totalRevenue: '0',
        popularCurrency: 'USD',
        topProduct: '',
        projectsDelivered: 0,
        clientRetention: 0,
        industryAwards: 0,
        supportTickets: 0,
        resolvedTickets: 0,
        activeProducts: 0,
        averageRating: 0,
        monthlyGrowth: 0,
        countries: 0,
        discordMembers: 0
    };
}

/**
 * Atualiza estatísticas agregadas
 */
async function updateAggregatedStats() {
    try {
        // Contar usuários totais
        const { count: totalUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });
        
        // Contar usuários ativos (com lastLogin nos últimos 30 dias)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const { count: activeUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .gte('lastLogin', thirtyDaysAgo.toISOString());
        
        // Contar pedidos completos e calcular receita
        const { data: completedOrders } = await supabase
            .from('orders')
            .select('amount')
            .eq('status', 'completed');
        
        const totalRevenue = completedOrders?.reduce((sum, order) => 
            sum + parseFloat(order.amount || 0), 0
        ) || 0;
        
        // Contar produtos ativos
        const { count: activeProducts } = await supabase
            .from('products')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'active');
        
        // Buscar produto mais baixado
        const { data: topProductData } = await supabase
            .from('products')
            .select('name, downloads')
            .order('downloads', { ascending: false })
            .limit(1);
        
        // Calcular média de avaliações
        const { data: reviews } = await supabase
            .from('reviews')
            .select('rating');
        
        const averageRating = reviews?.length ? 
            reviews.reduce((sum, r) => sum + (r.rating || 0), 0) / reviews.length : 0;
        
        // Atualizar tabela stats
        const stats = {
            totalUsers: totalUsers || 0,
            activeUsers: activeUsers || 0,
            totalOrders: completedOrders?.length || 0,
            totalRevenue: totalRevenue.toString(),
            topProduct: topProductData?.[0]?.name || '',
            activeProducts: activeProducts || 0,
            averageRating: parseFloat(averageRating.toFixed(1)),
            updatedAt: new Date().toISOString()
        };
        
        // Verificar se já existe registro de stats
        const { data: existingStats } = await supabase
            .from('stats')
            .select('id')
            .limit(1);
        
        if (existingStats?.length) {
            await supabase
                .from('stats')
                .update(stats)
                .eq('id', existingStats[0].id);
        } else {
            await supabase
                .from('stats')
                .insert([{ ...stats, id: 1 }]);
        }
        
    } catch (error) {
        console.error('Erro ao atualizar estatísticas:', error);
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token de acesso não fornecido' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido ou expirado' });
        }
        req.user = user;
        next();
    });
}

async function logActivity(event, details, userId = null, ip = '127.0.0.1') {
    try {
        await writeToSupabase('logs', {
            event,
            details,
            user_id: userId,
            timestamp: new Date().toISOString(),
            ip: ip
        });
        
    } catch (error) {
        console.error('Erro ao logar atividade:', error);
    }
}

async function syncAdminUser() {
    try {
        // Buscar admin existente
        const { data: existingAdmin } = await readFromSupabase('users', {
            filters: { username: ADMIN_USERNAME },
            single: true
        });
        
        const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
        
        if (existingAdmin) {
            // Atualizar admin existente
            await writeToSupabase('users', {
                password: hashedPassword,
                email: ADMIN_EMAIL || existingAdmin.email,
                lastUpdate: new Date().toISOString(),
                isAdmin: true
            }, 'update', { id: existingAdmin.id });
            
            await logActivity('ADMIN_UPDATED', `Credenciais do admin atualizadas`, existingAdmin.id);
            
        } else {
            // Criar novo admin
            const adminUser = {
                id: 'admin-' + Date.now().toString(),
                username: ADMIN_USERNAME,
                email: ADMIN_EMAIL,
                password: hashedPassword,
                profile: {
                    avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(ADMIN_USERNAME)}&background=00ff88&color=000&bold=true&size=256`,
                    bio: 'Administrador principal do sistema Lua Works',
                    location: 'Brasil',
                    website: 'https://lua-works.store',
                    social: {
                        discord: '',
                        github: '',
                        twitter: ''
                    }
                },
                preferences: {
                    theme: 'dark',
                    currency: 'USD',
                    notifications: true,
                    newsletter: false,
                    language: 'pt-BR'
                },
                orders: [],
                downloads: [],
                createdAt: new Date().toISOString(),
                lastLogin: new Date().toISOString(),
                lastActive: new Date().toISOString(),
                isAdmin: true,
                isVerified: true,
                twoFactorEnabled: false,
                apiKey: 'lw_' + crypto.randomBytes(16).toString('hex'),
                lastUpdate: new Date().toISOString()
            };
            
            await writeToSupabase('users', adminUser);
            await logActivity('ADMIN_CREATED', `Usuário admin inicializado: ${ADMIN_USERNAME}`, adminUser.id);
        }
        
        // Remover privilégios admin de outros usuários (exceto o admin principal)
        await supabase
            .from('users')
            .update({ isAdmin: false })
            .neq('username', ADMIN_USERNAME)
            .eq('isAdmin', true);
        
        // Atualizar estatísticas
        await updateAggregatedStats();
        
        return true;
        
    } catch (error) {
        console.error('Erro ao sincronizar admin:', error);
        return false;
    }
}

// ============================================
// ENDPOINTS (Refatorados para Supabase)
// ============================================

app.get('/api/crypto-prices', async (req, res) => {
    try {
        const prices = {
            BTC: 45000,
            ETH: 2500,
            USDT: 1,
            XRP: 0.5,
            BNB: 300,
            SOL: 100,
            LTC: 75,
            ADA: 0.45
        };
        
        res.json(prices);
    } catch (error) {
        console.error('Erro ao obter preços de criptomoedas:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/upload-file', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        // Verificar se usuário é admin
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            if (req.file) {
                await fs.unlink(req.file.path).catch(() => {});
            }
            return res.status(403).json({ error: 'Acesso negado' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Nenhum arquivo enviado' });
        }

        const fileInfo = {
            fileName: req.file.originalname,
            filePath: `/uploads/${req.file.filename}`,
            fileSize: req.file.size,
            mimeType: req.file.mimetype,
            uploadedAt: new Date().toISOString(),
            uploadedBy: user.id
        };

        await logActivity('FILE_UPLOADED', `Arquivo enviado: ${req.file.originalname} (${req.file.size} bytes)`, user.id, req.ip);

        res.json({
            success: true,
            message: 'Arquivo enviado com sucesso!',
            fileUrl: fileInfo.filePath,
            fileName: fileInfo.fileName,
            fileSize: fileInfo.fileSize,
            mimeType: fileInfo.mimeType
        });

    } catch (error) {
        console.error('Erro no upload:', error);
        
        if (req.file) {
            await fs.unlink(req.file.path).catch(() => {});
        }
        
        res.status(500).json({ 
            error: 'Erro interno do servidor no upload',
            details: error.message 
        });
    }
});

app.get('/api/download/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        
        // Buscar produto
        const product = await readFromSupabase('products', {
            filters: { id: productId },
            single: true
        });
        
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        if (!product.filePath) {
            return res.status(404).json({ error: 'Arquivo do produto não encontrado' });
        }

        const fileName = path.basename(product.filePath);
        const filePath = path.join(__dirname, product.filePath);
        
        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ error: 'Arquivo não encontrado no servidor' });
        }

        // Registrar download
        await writeToSupabase('downloads', {
            product_id: product.id,
            product_name: product.name,
            downloaded_at: new Date().toISOString(),
            ip: req.ip,
            user_agent: req.get('User-Agent')
        });

        // Atualizar contador de downloads do produto
        const newDownloads = (product.downloads || 0) + 1;
        await writeToSupabase('products', 
            { downloads: newDownloads }, 
            'update', 
            { id: product.id }
        );

        await logActivity('PRODUCT_DOWNLOADED', `Produto baixado: ${product.name}`, null, req.ip);

        const originalFileName = product.fileName || product.name.replace(/[^a-z0-9]/gi, '_') + path.extname(product.filePath);
        res.download(filePath, originalFileName);

    } catch (error) {
        console.error('Erro no download:', error);
        res.status(500).json({ error: 'Erro interno do servidor no download' });
    }
});

app.get('/api/download/:productId/authenticated', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.params;
        
        // Buscar produto
        const product = await readFromSupabase('products', {
            filters: { id: productId },
            single: true
        });
        
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        if (!product.filePath) {
            return res.status(404).json({ error: 'Arquivo do produto não encontrado' });
        }

        // Buscar usuário
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        // Verificar se usuário comprou o produto
        const { data: userOrders } = await supabase
            .from('orders')
            .select('product_id, status')
            .eq('user_id', user.id)
            .eq('product_id', productId)
            .eq('status', 'completed');

        const hasPurchased = userOrders && userOrders.length > 0;

        if (!hasPurchased && !user.isAdmin) {
            return res.status(403).json({ error: 'Você precisa comprar este produto para baixá-lo' });
        }

        const fileName = path.basename(product.filePath);
        const filePath = path.join(__dirname, product.filePath);
        
        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ error: 'Arquivo não encontrado no servidor' });
        }

        // Registrar download
        await writeToSupabase('downloads', {
            product_id: product.id,
            product_name: product.name,
            user_id: user.id,
            downloaded_at: new Date().toISOString(),
            ip: req.ip
        });

        // Atualizar contador de downloads
        const newDownloads = (product.downloads || 0) + 1;
        await writeToSupabase('products', 
            { downloads: newDownloads }, 
            'update', 
            { id: product.id }
        );

        await logActivity('PRODUCT_DOWNLOADED', `Produto baixado (autenticado): ${product.name}`, user.id, req.ip);

        const originalFileName = product.fileName || product.name.replace(/[^a-z0-9]/gi, '_') + path.extname(product.filePath);
        res.download(filePath, originalFileName);

    } catch (error) {
        console.error('Erro no download autenticado:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/verify-token', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await readFromSupabase('products');
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await readFromSupabase('products', {
            filters: { id: req.params.id },
            single: true
        });
        
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }
        
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/products/upcoming', async (req, res) => {
    try {
        const upcoming = await readFromSupabase('products', {
            filters: { status: 'upcoming' }
        });
        res.json(upcoming);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const stats = await readFromSupabase('stats', { single: true }) || generateDefaultStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/currencies', (req, res) => {
    const currencies = [
        { 
            id: 'bitcoin', 
            name: 'Bitcoin', 
            symbol: 'BTC', 
            icon: 'fab fa-bitcoin',
            color: '#f7931a',
            address: 'bc1q3xh8j8a0v00f9fhss7nxpxrl9hqk069gppw94w',
            network: 'Bitcoin Mainnet'
        },
        { 
            id: 'ethereum', 
            name: 'Ethereum', 
            symbol: 'ETH', 
            icon: 'fab fa-ethereum',
            color: '#627eea',
            address: '0xd75245E5807bBdE2f916fd48e537a78220a7713D',
            network: 'Ethereum Mainnet'
        },
        { 
            id: 'tether', 
            name: 'Tether', 
            symbol: 'USDT', 
            icon: 'fas fa-coins',
            color: '#26a17b',
            address: 'TZC559vuvL8uT6XN7PzHiSxGpDPsLRngLa',
            network: 'TRC20 (Tron)'
        },
        { 
            id: 'bnb', 
            name: 'BNB', 
            symbol: 'BNB', 
            icon: 'fab fa-btc',
            color: '#f0b90b',
            address: '0xd75245E5807bBdE2f916fd48e537a78220a7713D',
            network: 'BEP20 (Binance Smart Chain)'
        },
        { 
            id: 'solana', 
            name: 'Solana', 
            symbol: 'SOL', 
            icon: 'fas fa-sun',
            color: '#00ffa3',
            address: '8qpUpMp3hi9cvRjWncAAA3Da5hD36ecy5HdCzvqYW6nG',
            network: 'Solana Mainnet'
        },
        { 
            id: 'litecoin', 
            name: 'Litecoin', 
            symbol: 'LTC', 
            icon: 'fab fa-bitcoin',
            color: '#bfbbbb',
            address: 'ltc1qzcapvq8fytjtd4kxnt7srl2cm45um3rxf7h4j8',
            network: 'Litecoin Mainnet'
        }
    ];
    res.json(currencies);
});

app.get('/api/payment-info/:currency', (req, res) => {
    const { currency } = req.params;
    const currencyInfo = {
        BTC: {
            name: 'Bitcoin',
            symbol: 'BTC',
            address: 'bc1q3xh8j8a0v00f9fhss7nxpxrl9hqk069gppw94w',
            network: 'Bitcoin Mainnet',
            qrCode: 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=bitcoin:bc1q3xh8j8a0v00f9fhss7nxpxrl9hqk069gppw94w'
        },
        ETH: {
            name: 'Ethereum',
            symbol: 'ETH',
            address: '0xd75245E5807bBdE2f916fd48e537a78220a7713D',
            network: 'Ethereum Mainnet',
            qrCode: 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=ethereum:0xd75245E5807bBdE2f916fd48e537a78220a7713D'
        },
        USDT: {
            name: 'Tether',
            symbol: 'USDT',
            address: 'TZC559vuvL8uT6XN7PzHiSxGpDPsLRngLa',
            network: 'TRC20 (Tron)',
            qrCode: 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=tron:TZC559vuvL8uT6XN7PzHiSxGpDPsLRngLa'
        }
    };
    
    const info = currencyInfo[currency] || currencyInfo.BTC;
    res.json(info);
});

app.post('/api/calculate-crypto-price', async (req, res) => {
    try {
        const { usdAmount, cryptoCurrency } = req.body;
        
        if (!usdAmount || !cryptoCurrency) {
            return res.status(400).json({ error: 'Dados incompletos' });
        }
        
        const usd = parseFloat(usdAmount);
        if (isNaN(usd) || usd <= 0) {
            return res.status(400).json({ error: 'Valor em USD inválido' });
        }
        
        const cryptoPrices = {
            BTC: 45000,
            ETH: 2500,
            USDT: 1,
            XRP: 0.5,
            BNB: 300,
            SOL: 100,
            LTC: 75,
            ADA: 0.45
        };
        
        const price = cryptoPrices[cryptoCurrency];
        if (!price) {
            return res.status(400).json({ error: 'Criptomoeda não suportada' });
        }
        
        const cryptoAmount = usd / price;
        
        res.json({
            usdAmount: usd,
            cryptoCurrency,
            cryptoAmount: cryptoAmount,
            exchangeRate: price,
            formatted: {
                usd: `$${usd.toFixed(2)}`,
                crypto: `${cryptoAmount.toFixed(8)} ${cryptoCurrency}`
            }
        });
        
    } catch (error) {
        console.error('Erro ao calcular preço:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username e password são obrigatórios' });
        }

        // Buscar usuário pelo username
        const user = await readFromSupabase('users', {
            filters: { username: username.toLowerCase() },
            single: true
        });
        
        if (!user) {
            await logActivity('LOGIN_FAILED', `Tentativa de login com usuário inexistente: ${username}`, null, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            await logActivity('LOGIN_FAILED', `Senha incorreta para usuário: ${username}`, user.id, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        if (!user.isAdmin) {
            await logActivity('LOGIN_FAILED', `Usuário não-admin tentou acessar admin: ${username}`, user.id, req.ip);
            return res.status(403).json({ error: 'Acesso não autorizado. Apenas administradores.' });
        }

        // Atualizar lastLogin
        await writeToSupabase('users', 
            { lastLogin: new Date().toISOString(), lastActive: new Date().toISOString() }, 
            'update', 
            { id: user.id }
        );

        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email,
                isAdmin: user.isAdmin 
            },
            SECRET_KEY,
            { expiresIn: '30d' }
        );

        await logActivity('LOGIN_SUCCESS', `Admin ${username} fez login`, user.id, req.ip);

        res.json({
            message: 'Login realizado com sucesso!',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                profile: user.profile,
                preferences: user.preferences,
                orders: user.orders,
                downloads: user.downloads,
                isAdmin: user.isAdmin,
                isVerified: user.isVerified,
                apiKey: user.apiKey,
                createdAt: user.createdAt
            },
            token
        });

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/dashboard-stats', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Buscar estatísticas em tempo real
        const today = new Date().toDateString();
        const monthStart = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();
        
        // Total de usuários
        const { count: totalUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });
        
        // Usuários ativos (login nos últimos 30 dias)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const { count: activeUsers } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .gte('lastLogin', thirtyDaysAgo.toISOString());
        
        // Total de produtos
        const { count: totalProducts } = await supabase
            .from('products')
            .select('*', { count: 'exact', head: true });
        
        // Produtos ativos
        const { count: activeProducts } = await supabase
            .from('products')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'active');
        
        // Produtos upcoming
        const { count: upcomingProducts } = await supabase
            .from('products')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'upcoming');
        
        // Total de pedidos
        const { count: totalOrders } = await supabase
            .from('orders')
            .select('*', { count: 'exact', head: true });
        
        // Receita total (pedidos completos)
        const { data: completedOrders } = await supabase
            .from('orders')
            .select('amount')
            .eq('status', 'completed');
        
        const totalRevenue = completedOrders?.reduce((sum, o) => sum + parseFloat(o.amount || 0), 0) || 0;
        
        // Downloads hoje
        const { count: todayDownloads } = await supabase
            .from('downloads')
            .select('*', { count: 'exact', head: true })
            .gte('downloaded_at', new Date(today).toISOString());
        
        // Receita mensal
        const { data: monthlyOrders } = await supabase
            .from('orders')
            .select('amount')
            .eq('status', 'completed')
            .gte('created_at', monthStart);
        
        const monthlyRevenue = monthlyOrders?.reduce((sum, o) => sum + parseFloat(o.amount || 0), 0) || 0;
        
        // Logins hoje
        const { count: todayLogins } = await supabase
            .from('logs')
            .select('*', { count: 'exact', head: true })
            .eq('event', 'LOGIN_SUCCESS')
            .gte('timestamp', new Date(today).toISOString());
        
        // Tentativas falhas
        const { count: failedAttempts } = await supabase
            .from('logs')
            .select('*', { count: 'exact', head: true })
            .eq('event', 'LOGIN_FAILED');
        
        // IPs únicos
        const { data: logs } = await supabase
            .from('logs')
            .select('ip');
        
        const uniqueIPs = new Set(logs?.map(l => l.ip)).size;

        const detailedStats = {
            totalUsers: totalUsers || 0,
            activeUsers: activeUsers || 0,
            totalProducts: totalProducts || 0,
            activeProducts: activeProducts || 0,
            upcomingProducts: upcomingProducts || 0,
            totalOrders: totalOrders || 0,
            totalRevenue: totalRevenue,
            todayDownloads: todayDownloads || 0,
            monthlyRevenue: monthlyRevenue,
            todayLogins: todayLogins || 0,
            failedAttempts: failedAttempts || 0,
            uniqueIPs: uniqueIPs
        };

        res.json(detailedStats);

    } catch (error) {
        console.error('Erro ao buscar stats do dashboard:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/products', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const products = await readFromSupabase('products');
        res.json(products);

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/products', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const productData = req.body;
        
        if (!productData.name || !productData.description || !productData.price) {
            return res.status(400).json({ error: 'Dados do produto incompletos' });
        }

        const newProduct = {
            id: `prod-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            name: productData.name,
            description: productData.description,
            long_description: productData.longDescription || '',
            price: productData.price,
            original_price: productData.originalPrice || productData.price,
            currency: productData.currency || 'USD',
            category: productData.category || 'automation',
            features: productData.features ? 
                (Array.isArray(productData.features) ? 
                    productData.features : 
                    productData.features.split(',').map(f => f.trim())) : 
                [],
            status: productData.isUpcoming ? 'upcoming' : 'active',
            featured: productData.featured || false,
            upload_date: new Date().toISOString(),
            last_update: new Date().toISOString(),
            version: productData.version || '1.0.0',
            downloads: 0,
            rating: 0,
            tags: productData.tags ? 
                (Array.isArray(productData.tags) ? 
                    productData.tags : 
                    productData.tags.split(',').map(t => t.trim())) : 
                [],
            system_requirements: productData.systemRequirements || {},
            includes: productData.includes ? 
                (Array.isArray(productData.includes) ? 
                    productData.includes : 
                    productData.includes.split(',').map(i => i.trim())) : 
                [],
            file_size: productData.fileSize || '0 MB',
            file_path: productData.fileUrl || '',
            file_name: productData.fileName || '',
            developer: productData.developer || 'Lua Works Team',
            changelog: productData.changelog || []
        };

        await writeToSupabase('products', newProduct);

        await logActivity('PRODUCT_ADDED', `Produto adicionado: ${newProduct.name}`, user.id, req.ip);
        
        // Atualizar estatísticas
        await updateAggregatedStats();

        res.status(201).json({
            message: 'Produto criado com sucesso!',
            product: newProduct
        });

    } catch (error) {
        console.error('Erro ao criar produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.put('/api/admin/products/:id', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Verificar se produto existe
        const existingProduct = await readFromSupabase('products', {
            filters: { id: req.params.id },
            single: true
        });
        
        if (!existingProduct) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        const updatedProduct = {
            ...existingProduct,
            ...req.body,
            last_update: new Date().toISOString()
        };

        await writeToSupabase('products', 
            updatedProduct, 
            'update', 
            { id: req.params.id }
        );

        await logActivity('PRODUCT_UPDATED', `Produto atualizado: ${updatedProduct.name}`, user.id, req.ip);
        
        // Atualizar estatísticas
        await updateAggregatedStats();

        res.json({
            message: 'Produto atualizado com sucesso!',
            product: updatedProduct
        });

    } catch (error) {
        console.error('Erro ao atualizar produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.delete('/api/admin/products/:id', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Buscar produto para obter informações do arquivo
        const product = await readFromSupabase('products', {
            filters: { id: req.params.id },
            single: true
        });
        
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        // Remover arquivo associado
        if (product.file_path) {
            const filePath = path.join(__dirname, product.file_path);
            try {
                await fs.unlink(filePath);
                await logActivity('FILE_DELETED', `Arquivo removido: ${product.file_path}`, user.id, req.ip);
            } catch (error) {
                console.warn(`Arquivo não encontrado para remoção: ${filePath}`);
            }
        }

        // Excluir produto do banco
        await writeToSupabase('products', null, 'delete', { id: req.params.id });

        await logActivity('PRODUCT_DELETED', `Produto excluído: ${product.name}`, user.id, req.ip);
        
        // Atualizar estatísticas
        await updateAggregatedStats();

        res.json({
            message: 'Produto excluído com sucesso!'
        });

    } catch (error) {
        console.error('Erro ao excluir produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/recent-activity', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const recentActivity = await readFromSupabase('logs', {
            order: { column: 'timestamp', direction: 'desc' },
            limit: 10
        });

        res.json(recentActivity);

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/security-logs', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const securityLogs = await supabase
            .from('logs')
            .select('*')
            .or('event.ilike.%LOGIN%,event.ilike.%SECURITY%,event.ilike.%FILE%')
            .order('timestamp', { ascending: false })
            .limit(20);
        
        res.json(securityLogs.data || []);

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/reset-credentials', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const success = await syncAdminUser();
        
        if (success) {
            await logActivity('ADMIN_RESET', `Admin reiniciou credenciais do sistema`, user.id, req.ip);
            res.json({ 
                message: 'Credenciais do admin atualizadas com sucesso!',
                username: ADMIN_USERNAME,
                email: ADMIN_EMAIL
            });
        } else {
            res.status(500).json({ error: 'Erro ao atualizar credenciais' });
        }

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
        }

        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'Nome de usuário deve ter entre 3 e 20 caracteres' });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: 'Email inválido' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres' });
        }

        // Verificar se email já existe
        const { data: existingEmail } = await supabase
            .from('users')
            .select('id')
            .eq('email', email.toLowerCase())
            .limit(1);
        
        if (existingEmail?.length) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }
        
        // Verificar se username já existe
        const { data: existingUsername } = await supabase
            .from('users')
            .select('id')
            .eq('username', username.toLowerCase())
            .limit(1);
        
        if (existingUsername?.length) {
            return res.status(400).json({ error: 'Nome de usuário já existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        // 1. Criar usuário no Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.admin.createUser({
            email,
            password,
            email_confirm: true
        });
        
        if (authError) return res.status(500).json({ error: authError.message });

        // 2. Criar perfil na tabela 'users'
        const userProfile = {
            id: authData.user.id,
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password: hashedPassword,
            profile: {
                avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=00ff88&color=000&bold=true&size=256`,
                bio: ''
            },
            isAdmin: false,
            isVerified: true,
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString(),
            lastActive: new Date().toISOString()
        };

        const { error: insertError } = await supabase
            .from('users')
            .insert(userProfile);
            
        if (insertError) {
            // Rollback: excluir usuário do auth se falhar
            await supabase.auth.admin.deleteUser(authData.user.id);
            return res.status(500).json({ error: 'Falha ao criar usuário no banco' });
        }

        // 3. Gerar JWT
        const token = jwt.sign(
            { 
                id: authData.user.id, 
                username: username.toLowerCase(), 
                email: email.toLowerCase(), 
                isAdmin: false 
            },
            SECRET_KEY,
            { expiresIn: '30d' }
        );

        // 4. Logar atividade
        await logActivity('USER_REGISTERED', `Novo usuário registrado: ${username}`, authData.user.id, req.ip);
        
        // 5. Atualizar estatísticas
        await updateAggregatedStats();

        res.status(201).json({
            message: 'Usuário criado com sucesso!',
            user: {
                id: authData.user.id,
                username: username.toLowerCase(),
                email: email.toLowerCase(),
                profile: userProfile.profile,
                isAdmin: false
            },
            token
        });

    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }

        // Buscar usuário pelo email
        const user = await readFromSupabase('users', {
            filters: { email: email.toLowerCase() },
            single: true
        });
        
        if (!user) {
            await logActivity('LOGIN_FAILED', `Tentativa de login com email inexistente: ${email}`, null, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            await logActivity('LOGIN_FAILED', `Senha incorreta para email: ${email}`, user.id, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        // Atualizar lastLogin
        await writeToSupabase('users', 
            { lastLogin: new Date().toISOString(), lastActive: new Date().toISOString() }, 
            'update', 
            { id: user.id }
        );

        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email,
                isAdmin: user.isAdmin 
            },
            SECRET_KEY,
            { expiresIn: '30d' }
        );

        await logActivity('LOGIN_SUCCESS', `Usuário fez login: ${user.username}`, user.id, req.ip);

        res.json({
            message: 'Login realizado com sucesso!',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                profile: user.profile,
                preferences: user.preferences,
                orders: user.orders,
                downloads: user.downloads,
                isAdmin: user.isAdmin,
                isVerified: user.isVerified,
                apiKey: user.apiKey,
                createdAt: user.createdAt
            },
            token
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        // Atualizar lastActive
        await writeToSupabase('users', 
            { lastActive: new Date().toISOString() }, 
            'update', 
            { id: user.id }
        );

        res.json({
            id: user.id,
            username: user.username,
            email: user.email,
            profile: user.profile,
            preferences: user.preferences,
            orders: user.orders,
            downloads: user.downloads,
            isAdmin: user.isAdmin,
            isVerified: user.isVerified,
            apiKey: user.apiKey,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin,
            twoFactorEnabled: user.twoFactorEnabled
        });

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Buscar todos os usuários com informações resumidas
        const users = await readFromSupabase('users');
        
        // Buscar contagem de pedidos e downloads para cada usuário
        const usersWithStats = await Promise.all(users.map(async (u) => {
            const { count: orderCount } = await supabase
                .from('orders')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', u.id);
            
            const { count: downloadCount } = await supabase
                .from('downloads')
                .select('*', { count: 'exact', head: true })
                .eq('user_id', u.id);

            return {
                id: u.id,
                username: u.username,
                email: u.email,
                createdAt: u.createdAt,
                lastLogin: u.lastLogin,
                lastActive: u.lastActive,
                orders: orderCount || 0,
                downloads: downloadCount || 0,
                isAdmin: u.isAdmin,
                isVerified: u.isVerified
            };
        }));

        res.json(usersWithStats);

    } catch (error) {
        console.error('Erro ao buscar usuários:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const stats = await readFromSupabase('stats', { single: true }) || generateDefaultStats();
        
        // Buscar dados adicionais
        const { count: totalOrders } = await supabase
            .from('orders')
            .select('*', { count: 'exact', head: true });
        
        const { count: totalProducts } = await supabase
            .from('products')
            .select('*', { count: 'exact', head: true });
        
        const { count: activeProducts } = await supabase
            .from('products')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'active');
        
        const { count: upcomingProducts } = await supabase
            .from('products')
            .select('*', { count: 'exact', head: true })
            .eq('status', 'upcoming');
        
        // Receita total
        const { data: completedOrders } = await supabase
            .from('orders')
            .select('amount')
            .eq('status', 'completed');
        
        const totalRevenue = completedOrders?.reduce((sum, o) => sum + parseFloat(o.amount || 0), 0) || 0;
        
        // Downloads hoje
        const today = new Date().toDateString();
        const { count: todayDownloads } = await supabase
            .from('downloads')
            .select('*', { count: 'exact', head: true })
            .gte('downloaded_at', new Date(today).toISOString());
        
        // Receita mensal
        const monthStart = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();
        const { data: monthlyOrders } = await supabase
            .from('orders')
            .select('amount')
            .eq('status', 'completed')
            .gte('created_at', monthStart);
        
        const monthlyRevenue = monthlyOrders?.reduce((sum, o) => sum + parseFloat(o.amount || 0), 0) || 0;

        const detailedStats = {
            ...stats,
            totalOrders: totalOrders || 0,
            totalProducts: totalProducts || 0,
            activeProducts: activeProducts || 0,
            upcomingProducts: upcomingProducts || 0,
            totalRevenue: totalRevenue,
            todayDownloads: todayDownloads || 0,
            monthlyRevenue: monthlyRevenue
        };

        res.json(detailedStats);

    } catch (error) {
        console.error('Erro ao buscar stats admin:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/orders', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const orders = await readFromSupabase('orders');
        res.json(orders);

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/public/products', async (req, res) => {
    try {
        const products = await readFromSupabase('products');
        const publicProducts = products.map(p => ({
            id: p.id,
            name: p.name,
            description: p.description,
            price: p.price,
            currency: p.currency,
            category: p.category,
            features: p.features?.slice(0, 3) || [],
            status: p.status,
            featured: p.featured,
            uploadDate: p.upload_date,
            version: p.version,
            downloads: p.downloads || 0,
            rating: p.rating || 0,
            tags: p.tags || []
        }));
        
        res.json(publicProducts);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/public/stats', async (req, res) => {
    try {
        const stats = await readFromSupabase('stats', { single: true }) || generateDefaultStats();
        const publicStats = {
            projectsDelivered: stats.projectsDelivered || 0,
            clientRetention: stats.clientRetention || 0,
            industryAwards: stats.industryAwards || 0,
            activeProducts: stats.activeProducts || 0,
            averageRating: stats.averageRating || 0
        };
        
        res.json(publicStats);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/payments/verify', async (req, res) => {
    try {
        const { txHash, currency, amount, productId } = req.body;
        
        if (!txHash || !currency || !amount || !productId) {
            return res.status(400).json({ error: 'Dados incompletos' });
        }

        await logActivity('PAYMENT_VERIFICATION_ATTEMPT', 
            `Tentativa de verificação: ${currency} ${amount} - TX: ${txHash}`, 
            req.user?.id || null,
            req.ip
        );

        res.json({
            verified: true,
            message: 'Pagamento verificado com sucesso!',
            txHash: txHash,
            confirmations: 3,
            status: 'confirmed'
        });

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/backup', authenticateToken, async (req, res) => {
    try {
        const user = await readFromSupabase('users', {
            filters: { id: req.user.id },
            single: true
        });
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        // Nota: Backup de arquivos locais ainda necessário
        const backupDir = path.join(__dirname, 'backups');
        await fs.mkdir(backupDir, { recursive: true });
        
        const backupFile = path.join(backupDir, `backup-${Date.now()}.zip`);
        const archiver = require('archiver');
        const output = fsSync.createWriteStream(backupFile);
        const archive = archiver('zip', { zlib: { level: 9 } });
        
        output.on('close', () => {
            res.download(backupFile, `lua-works-backup-${Date.now()}.zip`, (err) => {
                if (err) {
                    console.error('Erro ao baixar backup:', err);
                }
                fs.unlink(backupFile).catch(() => {});
            });
        });
        
        archive.pipe(output);
        archive.directory(UPLOADS_PATH, 'uploads');
        archive.finalize();

    } catch (error) {
        console.error('Erro no backup:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/admin-login.html'));
});

app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/admin-dashboard.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(PUBLIC_PATH, 'index.html'));
});

async function startServer() {
    try {
        // Criar diretórios necessários
        await fs.mkdir(UPLOADS_PATH, { recursive: true });
        await fs.mkdir(PUBLIC_PATH, { recursive: true });
        await fs.mkdir(path.join(__dirname, 'backups'), { recursive: true });
        
        // Sincronizar admin
        await syncAdminUser();

        console.log(`Servidor Lua Works com Supabase iniciado com sucesso.`);

        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta ${PORT}`);
        });

    } catch (error) {
        console.error('Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

startServer().catch(console.error);
