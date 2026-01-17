// ==================== CONFIGURAÇÃO DO SERVIDOR ====================
const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs'); // Importação adicional para métodos síncronos
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'lua-works-real-secret-key-2024-v2';
const DB_PATH = path.join(__dirname, 'database');
const UPLOADS_PATH = path.join(__dirname, 'uploads');
const PUBLIC_PATH = path.join(__dirname, 'public'); // Caminho para a pasta public

// Configuração do multer para uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_PATH);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.lua', '.txt', '.zip', '.rar', '.7z'];
        const extname = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(extname)) {
            cb(null, true);
        } else {
            cb(new Error('Tipo de arquivo não permitido. Use .lua, .txt, .zip, .rar ou .7z'));
        }
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir arquivos estáticos CORRIGIDO para a hierarquia correta
app.use(express.static(PUBLIC_PATH)); // Primeiro serve os arquivos da pasta public
app.use('/uploads', express.static(UPLOADS_PATH)); // Depois a pasta uploads

// Garantir que os diretórios existem
async function ensureDirectories() {
    try {
        await fs.access(DB_PATH);
    } catch {
        await fs.mkdir(DB_PATH, { recursive: true });
    }
    
    try {
        await fs.access(UPLOADS_PATH);
    } catch {
        await fs.mkdir(UPLOADS_PATH, { recursive: true });
    }
    
    try {
        await fs.access(PUBLIC_PATH);
    } catch {
        await fs.mkdir(PUBLIC_PATH, { recursive: true });
    }
}

// ==================== FUNÇÕES DO BANCO DE DADOS ====================
async function readDatabase(file) {
    try {
        const data = await fs.readFile(path.join(DB_PATH, file), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // Se o arquivo não existe, retorna estrutura padrão
        if (file === 'users.json') return { users: [] };
        if (file === 'products.json') return await generateRealProducts();
        if (file === 'orders.json') return { orders: [] };
        if (file === 'stats.json') return await generateRealStats();
        if (file === 'downloads.json') return { downloads: [] };
        if (file === 'reviews.json') return { reviews: [] };
        if (file === 'logs.json') return { logs: [] };
        return [];
    }
}

async function writeDatabase(file, data) {
    await fs.writeFile(path.join(DB_PATH, file), JSON.stringify(data, null, 2));
}

// ==================== DADOS REAIS ====================
async function generateRealProducts() {
    return []; // Array vazio - todos os produtos foram removidos
}

async function generateRealStats() {
    const products = await generateRealProducts();
    const activeProducts = products.filter(p => p.status === 'active');
    
    return {
        totalUsers: 0,
        activeUsers: 0,
        totalOrders: 0,
        totalRevenue: '0',
        popularCurrency: 'BTC',
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

// ==================== MIDDLEWARE DE AUTENTICAÇÃO ====================
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

// Middleware para logar atividades
async function logActivity(event, details, userId = null) {
    try {
        const logsDb = await readDatabase('logs.json');
        logsDb.logs.push({
            id: `LOG-${Date.now()}`,
            event,
            details,
            userId,
            timestamp: new Date().toISOString(),
            ip: '127.0.0.1' // Em produção, usar req.ip
        });
        await writeDatabase('logs.json', logsDb);
    } catch (error) {
        console.error('Erro ao registrar log:', error);
    }
}

// ==================== ROTAS DA API ====================

// Rota para verificar token
app.get('/api/verify-token', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// Produtos
app.get('/api/products', async (req, res) => {
    try {
        const products = await readDatabase('products.json');
        res.json(products);
    } catch (error) {
        console.error('Erro ao ler produtos:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const products = await readDatabase('products.json');
        const product = products.find(p => p.id === req.params.id);
        
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }
        
        res.json(product);
    } catch (error) {
        console.error('Erro ao buscar produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/products/upcoming', async (req, res) => {
    try {
        const products = await readDatabase('products.json');
        const upcoming = products.filter(p => p.status === 'upcoming');
        res.json(upcoming);
    } catch (error) {
        console.error('Erro ao ler produtos:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Estatísticas
app.get('/api/stats', async (req, res) => {
    try {
        const stats = await readDatabase('stats.json');
        res.json(stats);
    } catch (error) {
        console.error('Erro ao ler estatísticas:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Moedas
app.get('/api/currencies', (req, res) => {
    const currencies = [
        { 
            id: 'bitcoin', 
            name: 'Bitcoin', 
            symbol: 'BTC', 
            icon: 'fab fa-bitcoin',
            color: '#f7931a',
            address: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
            network: 'Bitcoin Mainnet'
        },
        { 
            id: 'ethereum', 
            name: 'Ethereum', 
            symbol: 'ETH', 
            icon: 'fab fa-ethereum',
            color: '#627eea',
            address: '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
            network: 'Ethereum Mainnet'
        },
        { 
            id: 'tether', 
            name: 'Tether', 
            symbol: 'USDT', 
            icon: 'fas fa-coins',
            color: '#26a17b',
            address: 'TNSgRrJjU9vCh3qLgJoj5gLk7Wb9Xr1R6F',
            network: 'TRC20'
        },
        { 
            id: 'bnb', 
            name: 'BNB', 
            symbol: 'BNB', 
            icon: 'fab fa-btc',
            color: '#f0b90b',
            address: 'bnb136ns6lfw4s5hg4n85vthaad7hq5m4gtkgf23a',
            network: 'BEP20'
        },
        { 
            id: 'solana', 
            name: 'Solana', 
            symbol: 'SOL', 
            icon: 'fas fa-sun',
            color: '#00ffa3',
            address: '7WZ7zQ7mFQK2qK7Q2K7Q2K7Q2K7Q2K7Q2K7Q2K7Q',
            network: 'Solana'
        },
        { 
            id: 'litecoin', 
            name: 'Litecoin', 
            symbol: 'LTC', 
            icon: 'fab fa-bitcoin',
            color: '#bfbbbb',
            address: 'LcF8b2m7p3j6Qa9T4wX1zY5v8K0n',
            network: 'Litecoin'
        }
    ];
    res.json(currencies);
});

// ==================== ROTAS ADMIN ====================

// Rota de login admin
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username e password são obrigatórios' });
        }

        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (!user) {
            await logActivity('LOGIN_FAILED', `Tentativa de login com usuário inexistente: ${username}`);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            await logActivity('LOGIN_FAILED', `Senha incorreta para usuário: ${username}`, user.id);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        if (!user.isAdmin) {
            await logActivity('LOGIN_FAILED', `Usuário não-admin tentou acessar admin: ${username}`, user.id);
            return res.status(403).json({ error: 'Acesso não autorizado. Apenas administradores.' });
        }

        // Atualizar último login
        user.lastLogin = new Date().toISOString();
        user.lastActive = new Date().toISOString();
        await writeDatabase('users.json', db);

        // Gerar token
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

        await logActivity('LOGIN_SUCCESS', `Admin ${username} fez login`, user.id);

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
        console.error('Erro no login admin:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Dashboard admin
app.get('/api/admin/dashboard-stats', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const stats = await readDatabase('stats.json');
        const ordersDb = await readDatabase('orders.json');
        const productsDb = await readDatabase('products.json');
        const downloadsDb = await readDatabase('downloads.json');
        const usersDb = await readDatabase('users.json');
        const logsDb = await readDatabase('logs.json');

        const detailedStats = {
            totalUsers: usersDb.users.length,
            activeUsers: usersDb.users.filter(u => u.lastLogin).length,
            totalProducts: productsDb.length,
            activeProducts: productsDb.filter(p => p.status === 'active').length,
            upcomingProducts: productsDb.filter(p => p.status === 'upcoming').length,
            totalOrders: ordersDb.orders.length,
            totalRevenue: ordersDb.orders
                .filter(o => o.status === 'completed')
                .reduce((sum, o) => sum + parseFloat(o.amount), 0),
            todayDownloads: downloadsDb.downloads.filter(d => {
                const today = new Date().toDateString();
                return new Date(d.downloadedAt).toDateString() === today;
            }).length,
            monthlyRevenue: ordersDb.orders
                .filter(o => {
                    const orderDate = new Date(o.createdAt);
                    const now = new Date();
                    return orderDate.getMonth() === now.getMonth() && 
                           orderDate.getFullYear() === now.getFullYear();
                })
                .reduce((sum, o) => sum + parseFloat(o.amount), 0),
            todayLogins: logsDb.logs.filter(l => {
                const today = new Date().toDateString();
                return l.event === 'LOGIN_SUCCESS' && 
                       new Date(l.timestamp).toDateString() === today;
            }).length,
            failedAttempts: logsDb.logs.filter(l => l.event === 'LOGIN_FAILED').length,
            uniqueIPs: [...new Set(logsDb.logs.map(l => l.ip))].length
        };

        res.json(detailedStats);

    } catch (error) {
        console.error('Erro ao buscar estatísticas do dashboard:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Produtos admin
app.get('/api/admin/products', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const products = await readDatabase('products.json');
        res.json(products);

    } catch (error) {
        console.error('Erro ao buscar produtos admin:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/products', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const productData = req.body;
        
        if (!productData.name || !productData.description || !productData.price) {
            return res.status(400).json({ error: 'Dados do produto incompletos' });
        }

        const productsDb = await readDatabase('products.json');
        
        const newProduct = {
            id: productData.id || `prod-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            name: productData.name,
            description: productData.description,
            longDescription: productData.longDescription || '',
            price: productData.price,
            originalPrice: productData.originalPrice || productData.price,
            currency: productData.currency || 'BTC',
            category: productData.category || 'automation',
            features: productData.features ? productData.features.split(',').map(f => f.trim()) : [],
            status: productData.isUpcoming ? 'upcoming' : 'active',
            featured: productData.featured || false,
            uploadDate: new Date().toISOString(),
            lastUpdate: new Date().toISOString(),
            version: productData.version || '1.0.0',
            downloads: 0,
            rating: 0,
            tags: productData.tags ? productData.tags.split(',').map(t => t.trim()) : [],
            systemRequirements: productData.systemRequirements || {},
            includes: productData.includes ? productData.includes.split(',').map(i => i.trim()) : [],
            fileSize: req.file ? `${(req.file.size / (1024 * 1024)).toFixed(1)} MB` : '0 MB',
            filePath: req.file ? `/uploads/${req.file.filename}` : '',
            developer: productData.developer || 'Lua Works Team',
            changelog: productData.changelog || []
        };

        productsDb.push(newProduct);
        await writeDatabase('products.json', productsDb);

        await logActivity('PRODUCT_ADDED', `Produto adicionado: ${newProduct.name}`, user.id);

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
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const productsDb = await readDatabase('products.json');
        const productIndex = productsDb.findIndex(p => p.id === req.params.id);
        
        if (productIndex === -1) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        const updatedProduct = {
            ...productsDb[productIndex],
            ...req.body,
            lastUpdate: new Date().toISOString()
        };

        productsDb[productIndex] = updatedProduct;
        await writeDatabase('products.json', productsDb);

        await logActivity('PRODUCT_UPDATED', `Produto atualizado: ${updatedProduct.name}`, user.id);

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
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const productsDb = await readDatabase('products.json');
        const productIndex = productsDb.findIndex(p => p.id === req.params.id);
        
        if (productIndex === -1) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        const deletedProduct = productsDb[productIndex];
        productsDb.splice(productIndex, 1);
        await writeDatabase('products.json', productsDb);

        await logActivity('PRODUCT_DELETED', `Produto excluído: ${deletedProduct.name}`, user.id);

        res.json({
            message: 'Produto excluído com sucesso!'
        });

    } catch (error) {
        console.error('Erro ao excluir produto:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Atividade recente
app.get('/api/admin/recent-activity', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const logsDb = await readDatabase('logs.json');
        const recentActivity = logsDb.logs
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 10);

        res.json(recentActivity);

    } catch (error) {
        console.error('Erro ao buscar atividade recente:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// Logs de segurança
app.get('/api/admin/security-logs', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const logsDb = await readDatabase('logs.json');
        const securityLogs = logsDb.logs
            .filter(l => l.event.includes('LOGIN') || l.event.includes('SECURITY'))
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 20);

        res.json(securityLogs);

    } catch (error) {
        console.error('Erro ao buscar logs de segurança:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ==================== AUTENTICAÇÃO USUÁRIO ====================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Validação
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

        const db = await readDatabase('users.json');
        
        // Verificar se usuário já existe
        if (db.users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }
        
        if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
            return res.status(400).json({ error: 'Nome de usuário já existe' });
        }

        // Hash da senha
        const hashedPassword = await bcrypt.hash(password, 12);
        
        const newUser = {
            id: Date.now().toString(),
            username,
            email,
            password: hashedPassword,
            profile: {
                avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=00ff88&color=000&bold=true&size=256`,
                bio: '',
                location: '',
                website: '',
                social: {
                    discord: '',
                    github: '',
                    twitter: ''
                }
            },
            preferences: {
                theme: 'dark',
                currency: 'BTC',
                notifications: true,
                newsletter: true,
                language: 'pt-BR'
            },
            orders: [],
            downloads: [],
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString(),
            lastActive: new Date().toISOString(),
            isAdmin: db.users.length === 0, // Primeiro usuário é admin
            isVerified: false,
            twoFactorEnabled: false,
            apiKey: 'lw_' + require('crypto').randomBytes(16).toString('hex')
        };

        db.users.push(newUser);
        await writeDatabase('users.json', db);

        // Atualizar estatísticas
        const stats = await readDatabase('stats.json');
        stats.totalUsers = db.users.length;
        stats.activeUsers = db.users.filter(u => u.lastLogin).length;
        await writeDatabase('stats.json', stats);

        // Gerar token
        const token = jwt.sign(
            { 
                id: newUser.id, 
                username: newUser.username, 
                email: newUser.email,
                isAdmin: newUser.isAdmin 
            },
            SECRET_KEY,
            { expiresIn: '30d' }
        );

        await logActivity('USER_REGISTERED', `Novo usuário registrado: ${username}`, newUser.id);

        res.status(201).json({
            message: 'Usuário criado com sucesso!',
            user: {
                id: newUser.id,
                username: newUser.username,
                email: newUser.email,
                profile: newUser.profile,
                preferences: newUser.preferences,
                isAdmin: newUser.isAdmin,
                isVerified: newUser.isVerified,
                apiKey: newUser.apiKey
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

        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
        
        if (!user) {
            await logActivity('LOGIN_FAILED', `Tentativa de login com email inexistente: ${email}`);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            await logActivity('LOGIN_FAILED', `Senha incorreta para email: ${email}`, user.id);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        // Atualizar último login
        user.lastLogin = new Date().toISOString();
        user.lastActive = new Date().toISOString();
        await writeDatabase('users.json', db);

        // Gerar token
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

        await logActivity('LOGIN_SUCCESS', `Usuário fez login: ${user.username}`, user.id);

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
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        // Atualizar última atividade
        user.lastActive = new Date().toISOString();
        await writeDatabase('users.json', db);

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
        console.error('Erro ao buscar usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ==================== ROTAS ADMIN EXISTENTES ====================
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const users = db.users.map(u => ({
            id: u.id,
            username: u.username,
            email: u.email,
            createdAt: u.createdAt,
            lastLogin: u.lastLogin,
            lastActive: u.lastActive,
            orders: u.orders.length,
            downloads: u.downloads.length,
            isAdmin: u.isAdmin,
            isVerified: u.isVerified
        }));

        res.json(users);

    } catch (error) {
        console.error('Erro ao buscar usuários:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const stats = await readDatabase('stats.json');
        const ordersDb = await readDatabase('orders.json');
        const productsDb = await readDatabase('products.json');
        const downloadsDb = await readDatabase('downloads.json');

        const detailedStats = {
            ...stats,
            totalOrders: ordersDb.orders.length,
            totalProducts: productsDb.length,
            activeProducts: productsDb.filter(p => p.status === 'active').length,
            upcomingProducts: productsDb.filter(p => p.status === 'upcoming').length,
            totalRevenue: ordersDb.orders
                .filter(o => o.status === 'completed')
                .reduce((sum, o) => sum + parseFloat(o.amount), 0),
            todayDownloads: downloadsDb.downloads.filter(d => {
                const today = new Date().toDateString();
                return new Date(d.downloadedAt).toDateString() === today;
            }).length,
            monthlyRevenue: ordersDb.orders
                .filter(o => {
                    const orderDate = new Date(o.createdAt);
                    const now = new Date();
                    return orderDate.getMonth() === now.getMonth() && 
                           orderDate.getFullYear() === now.getFullYear();
                })
                .reduce((sum, o) => sum + parseFloat(o.amount), 0)
        };

        res.json(detailedStats);

    } catch (error) {
        console.error('Erro ao buscar estatísticas:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/orders', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const ordersDb = await readDatabase('orders.json');
        
        res.json(ordersDb.orders);

    } catch (error) {
        console.error('Erro ao buscar pedidos:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ==================== ROTAS PÚBLICAS ====================
app.get('/api/public/products', async (req, res) => {
    try {
        const products = await readDatabase('products.json');
        const publicProducts = products.map(p => ({
            id: p.id,
            name: p.name,
            description: p.description,
            price: p.price,
            currency: p.currency,
            category: p.category,
            features: p.features.slice(0, 3),
            status: p.status,
            featured: p.featured,
            uploadDate: p.uploadDate,
            version: p.version,
            downloads: p.downloads,
            rating: p.rating,
            tags: p.tags
        }));
        
        res.json(publicProducts);
    } catch (error) {
        console.error('Erro ao buscar produtos públicos:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/public/stats', async (req, res) => {
    try {
        const stats = await readDatabase('stats.json');
        const publicStats = {
            projectsDelivered: stats.projectsDelivered,
            clientRetention: stats.clientRetention,
            industryAwards: stats.industryAwards,
            activeProducts: stats.activeProducts,
            averageRating: stats.averageRating
        };
        
        res.json(publicStats);
    } catch (error) {
        console.error('Erro ao buscar estatísticas públicas:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ==================== BACKUP ====================
app.get('/api/admin/backup', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const backupDir = path.join(__dirname, 'backups');
        await fs.mkdir(backupDir, { recursive: true });
        
        const backupFile = path.join(backupDir, `backup-${Date.now()}.zip`);
        const archiver = require('archiver');
        const output = fsSync.createWriteStream(backupFile);
        const archive = archiver('zip', { zlib: { level: 9 } });
        
        output.on('close', () => {
            res.download(backupFile, `lua-works-backup-${Date.now()}.zip`, (err) => {
                if (err) {
                    console.error('Erro ao enviar backup:', err);
                }
                // Limpar arquivo após download
                fs.unlink(backupFile).catch(() => {});
            });
        });
        
        archive.pipe(output);
        archive.directory(DB_PATH, 'database');
        archive.finalize();

    } catch (error) {
        console.error('Erro ao criar backup:', error);
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

// ==================== ROTAS DE ADMIN INTERFACE ====================
// Rota para servir admin login
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/admin-login.html'));
});

// Rota para servir admin dashboard
app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/admin-dashboard.html'));
});

// ==================== ROTA PARA SERVIR INDEX.HTML ====================
// Esta rota precisa ser ajustada para servir o index.html da pasta public
app.get('*', (req, res) => {
    res.sendFile(path.join(PUBLIC_PATH, 'index.html'));
});

// ==================== INICIALIZAR SERVIDOR ====================
async function startServer() {
    try {
        await ensureDirectories();
        
        // Verificar se a pasta public existe
        try {
            await fs.access(PUBLIC_PATH);
            console.log(`📁 Pasta public encontrada: ${PUBLIC_PATH}`);
            
            // Verificar se index.html existe na pasta public
            const indexPath = path.join(PUBLIC_PATH, 'index.html');
            try {
                await fs.access(indexPath);
                console.log('✅ index.html encontrado na pasta public');
            } catch {
                console.warn('⚠️ index.html não encontrado na pasta public');
            }
        } catch {
            console.warn('⚠️ Pasta public não encontrada, criando...');
            await fs.mkdir(PUBLIC_PATH, { recursive: true });
        }
        
        // Inicializar dados se não existirem
        const products = await readDatabase('products.json');
        if (products.length === 0) {
            await writeDatabase('products.json', await generateRealProducts());
        }
        
        const stats = await readDatabase('stats.json');
        if (!stats.totalUsers) {
            await writeDatabase('stats.json', await generateRealStats());
        }

        // Inicializar arquivo de logs se não existir
        try {
            await readDatabase('logs.json');
        } catch {
            await writeDatabase('logs.json', { logs: [] });
        }

        // Criar arquivos de download simulado
        const realProducts = await generateRealProducts();
        for (const product of realProducts) {
            if (product.status === 'active' && product.filePath) {
                const fileName = path.basename(product.filePath);
                const filePath = path.join(UPLOADS_PATH, fileName);
                
                try {
                    await fs.access(filePath);
                } catch {
                    // Criar arquivo simulado
                    const archiver = require('archiver');
                    const output = fsSync.createWriteStream(filePath);
                    const archive = archiver('zip', { zlib: { level: 9 } });
                    
                    output.on('close', () => {
                        console.log(`✅ Arquivo criado: ${fileName}`);
                    });
                    
                    archive.pipe(output);
                    archive.append(`-- ${product.name} v${product.version}\n-- Premium Script by Lua Works\n-- www.luaworks.dev\n\nprint("${product.name} carregado com sucesso!")`, { name: 'main.lua' });
                    archive.append(`# ${product.name}\n\nPremium Lua script for Roblox.\n\n## Features\n${product.features.map(f => `- ${f}`).join('\n')}\n\n## Installation\n1. Extract files\n2. Run main.lua\n3. Enjoy!`, { name: 'README.md' });
                    archive.finalize();
                }
            }
        }

        app.listen(PORT, () => {
            console.log(`🐂 Servidor rodando na porta ${PORT}`);
        });

    } catch (error) {
        console.error('✖ Erro ao iniciar servidor:', error);
        process.exit(1);
    }
}

// Iniciar servidor
startServer().catch(console.error);

// Tratar erros não capturados
process.on('uncaughtException', (error) => {
    console.error('✖ Erro não capturado:', error);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('✖ Promessa rejeitada não tratada:', reason);
});
