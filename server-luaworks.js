const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const validator = require('validator');
const { cryptoRandomString } = require('crypto-random-string');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || cryptoRandomString({length: 128, type: 'base64'});

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'FisherMAN1909';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'N10Sz!@,;>';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'laila.cypher19@proton.me';

const DB_PATH = path.join(__dirname, 'database');
const UPLOADS_PATH = path.join(__dirname, 'uploads');
const PUBLIC_PATH = path.join(__dirname, 'public');
const WHITELISTED_IPS = (process.env.WHITELISTED_IPS || '').split(',').filter(ip => ip.trim());
const BLACKLISTED_IPS = (process.env.BLACKLISTED_IPS || '').split(',').filter(ip => ip.trim());

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Muitas requisições deste IP, tente novamente mais tarde.',
    skipSuccessfulRequests: false
});

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: 'Muitas tentativas de login, tente novamente em uma hora.',
    skipSuccessfulRequests: false
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    message: 'Muitas requisições administrativas, tente novamente mais tarde.',
    skipSuccessfulRequests: false
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_PATH);
    },
    filename: (req, file, cb) => {
        const timestamp = Date.now();
        const random = crypto.randomBytes(8).toString('hex');
        const originalName = path.parse(file.originalname).name;
        const extension = path.extname(file.originalname);
        const sanitizedName = originalName.replace(/[^a-zA-Z0-9]/g, '_');
        const uniqueName = `${sanitizedName}_${timestamp}_${random}${extension}`;
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

function validateInput(input, type) {
    if (!input) return false;
    
    switch(type) {
        case 'email':
            return validator.isEmail(input) && validator.isLength(input, { max: 255 });
        case 'username':
            return validator.isAlphanumeric(input.replace(/[_-]/g, '')) && 
                   validator.isLength(input, { min: 3, max: 20 });
        case 'password':
            return validator.isLength(input, { min: 8 }) &&
                   /[A-Z]/.test(input) &&
                   /[a-z]/.test(input) &&
                   /[0-9]/.test(input) &&
                   /[^A-Za-z0-9]/.test(input);
        case 'text':
            return validator.isLength(input, { max: 1000 }) &&
                   !/<script|javascript:|on\w+\s*=/.test(input.toLowerCase());
        case 'filename':
            return validator.isLength(input, { max: 255 }) &&
                   !/[<>:"/\\|?*]/.test(input) &&
                   !input.includes('..');
        default:
            return validator.isLength(input, { max: 500 });
    }
}

function ipSecurityMiddleware(req, res, next) {
    const clientIp = req.ip || req.connection.remoteAddress;
    
    if (BLACKLISTED_IPS.includes(clientIp)) {
        return res.status(403).json({ error: 'Acesso bloqueado' });
    }
    
    if (WHITELISTED_IPS.length > 0 && !WHITELISTED_IPS.includes(clientIp)) {
        return res.status(403).json({ error: 'Acesso não autorizado' });
    }
    
    next();
}

function sanitizeData(data) {
    if (typeof data === 'string') {
        return validator.escape(data.replace(/<[^>]*>?/gm, ''));
    }
    if (Array.isArray(data)) {
        return data.map(item => sanitizeData(item));
    }
    if (typeof data === 'object' && data !== null) {
        const sanitized = {};
        for (const key in data) {
            sanitized[key] = sanitizeData(data[key]);
        }
        return sanitized;
    }
    return data;
}

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(mongoSanitize());
app.use(hpp());
app.use(ipSecurityMiddleware);

app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/admin/', adminLimiter);

app.use(express.static(PUBLIC_PATH, {
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
    }
}));
app.use('/uploads', express.static(UPLOADS_PATH, {
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Content-Disposition', 'attachment');
    }
}));

async function readDatabase(file) {
    try {
        const filePath = path.join(DB_PATH, file);
        if (!filePath.startsWith(DB_PATH)) {
            throw new Error('Caminho inválido');
        }
        
        const data = await fs.readFile(filePath, 'utf8');
        const parsed = JSON.parse(data);
        return sanitizeData(parsed);
    } catch (error) {
        if (file === 'users.json') return { users: [] };
        if (file === 'products.json') return [];
        if (file === 'orders.json') return { orders: [] };
        if (file === 'stats.json') return await generateRealStats();
        if (file === 'downloads.json') return { downloads: [] };
        if (file === 'reviews.json') return { reviews: [] };
        if (file === 'logs.json') return { logs: [] };
        if (file === 'security.json') return { failedAttempts: [], blockedIPs: [] };
        return [];
    }
}

async function writeDatabase(file, data) {
    const filePath = path.join(DB_PATH, file);
    if (!filePath.startsWith(DB_PATH)) {
        throw new Error('Caminho inválido');
    }
    
    const sanitizedData = sanitizeData(data);
    await fs.writeFile(filePath, JSON.stringify(sanitizedData, null, 2));
}

async function generateRealStats() {
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

async function checkFailedAttempts(ip, identifier) {
    try {
        const securityDb = await readDatabase('security.json');
        const now = Date.now();
        const oneHourAgo = now - (60 * 60 * 1000);
        
        securityDb.failedAttempts = securityDb.failedAttempts.filter(attempt => 
            attempt.timestamp > oneHourAgo
        );
        
        const ipAttempts = securityDb.failedAttempts.filter(a => a.ip === ip);
        const identifierAttempts = securityDb.failedAttempts.filter(a => a.identifier === identifier);
        
        if (ipAttempts.length >= 10 || identifierAttempts.length >= 5) {
            securityDb.blockedIPs.push({
                ip: ip,
                blockedAt: now,
                reason: 'Muitas tentativas falhas'
            });
            await writeDatabase('security.json', securityDb);
            return true;
        }
        
        return false;
    } catch (error) {
        return false;
    }
}

async function recordFailedAttempt(ip, identifier) {
    try {
        const securityDb = await readDatabase('security.json');
        securityDb.failedAttempts.push({
            ip: ip,
            identifier: identifier,
            timestamp: Date.now()
        });
        await writeDatabase('security.json', securityDb);
    } catch (error) {
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
        
        if (!user || !user.id || !user.username) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        
        req.user = user;
        next();
    });
}

async function logActivity(event, details, userId = null, ip = '127.0.0.1') {
    try {
        const logsDb = await readDatabase('logs.json');
        logsDb.logs.push({
            id: `LOG-${Date.now()}-${cryptoRandomString({length: 8, type: 'alphanumeric'})}`,
            event,
            details: validator.escape(details.substring(0, 1000)),
            userId,
            timestamp: new Date().toISOString(),
            ip: ip
        });
        
        if (logsDb.logs.length > 10000) {
            logsDb.logs = logsDb.logs.slice(-5000);
        }
        
        await writeDatabase('logs.json', logsDb);
    } catch (error) {
    }
}

async function syncAdminUser() {
    try {
        const db = await readDatabase('users.json');
        
        const adminExists = db.users.find(u => u.username === ADMIN_USERNAME);
        
        if (adminExists) {
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
            adminExists.password = hashedPassword;
            adminExists.email = ADMIN_EMAIL || adminExists.email;
            adminExists.lastUpdate = new Date().toISOString();
            
            await logActivity('ADMIN_UPDATED', `Credenciais do admin atualizadas`, adminExists.id);
            
        } else {
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12);
            
            const adminUser = {
                id: 'admin-' + Date.now().toString() + '-' + cryptoRandomString({length: 8, type: 'alphanumeric'}),
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
                apiKey: 'lw_' + crypto.randomBytes(32).toString('hex'),
                lastUpdate: new Date().toISOString()
            };
            
            db.users.push(adminUser);
            
            await logActivity('ADMIN_CREATED', `Usuário admin inicializado: ${ADMIN_USERNAME}`, adminUser.id);
        }
        
        db.users.forEach(user => {
            if (user.username !== ADMIN_USERNAME && user.isAdmin) {
                user.isAdmin = false;
                logActivity('ADMIN_DEMOTED', `Usuário ${user.username} teve privilégios admin removidos`, user.id);
            }
        });
        
        await writeDatabase('users.json', db);
        
        const stats = await readDatabase('stats.json');
        stats.totalUsers = db.users.length;
        stats.activeUsers = db.users.filter(u => u.lastLogin).length;
        await writeDatabase('stats.json', stats);
        
        return true;
        
    } catch (error) {
        return false;
    }
}

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
        
        res.setHeader('Cache-Control', 'public, max-age=60');
        res.json(prices);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/upload-file', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            if (req.file) {
                await fs.unlink(req.file.path).catch(() => {});
            }
            return res.status(403).json({ error: 'Acesso negado' });
        }

        if (!req.file) {
            return res.status(400).json({ error: 'Nenhum arquivo enviado' });
        }

        const fileExtension = path.extname(req.file.originalname).toLowerCase();
        const allowedExtensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.js', '.json', '.py', '.xml', '.html', '.css', '.md', '.lua'];
        
        if (!allowedExtensions.includes(fileExtension)) {
            await fs.unlink(req.file.path).catch(() => {});
            return res.status(400).json({ error: 'Tipo de arquivo não permitido' });
        }

        const maxSize = 100 * 1024 * 1024;
        if (req.file.size > maxSize) {
            await fs.unlink(req.file.path).catch(() => {});
            return res.status(400).json({ error: 'Arquivo muito grande' });
        }

        const fileInfo = {
            fileName: validator.escape(req.file.originalname.substring(0, 255)),
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
        if (req.file) {
            await fs.unlink(req.file.path).catch(() => {});
        }
        
        res.status(500).json({ 
            error: 'Erro interno do servidor no upload'
        });
    }
});

app.get('/api/download/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        
        if (!validateInput(productId, 'text')) {
            return res.status(400).json({ error: 'ID do produto inválido' });
        }
        
        const productsDb = await readDatabase('products.json');
        const product = productsDb.find(p => p.id === productId);
        
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

        const downloadsDb = await readDatabase('downloads.json');
        downloadsDb.downloads.push({
            productId: product.id,
            productName: product.name,
            downloadedAt: new Date().toISOString(),
            ip: req.ip,
            userAgent: req.get('User-Agent') ? req.get('User-Agent').substring(0, 500) : 'Desconhecido'
        });
        await writeDatabase('downloads.json', downloadsDb);

        product.downloads = (product.downloads || 0) + 1;
        await writeDatabase('products.json', productsDb);

        await logActivity('PRODUCT_DOWNLOADED', `Produto baixado: ${product.name}`, null, req.ip);

        const originalFileName = product.fileName || product.name.replace(/[^a-z0-9]/gi, '_') + path.extname(product.filePath);
        res.setHeader('Content-Disposition', `attachment; filename="${originalFileName}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.download(filePath, originalFileName);

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor no download' });
    }
});

app.get('/api/download/:productId/authenticated', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.params;
        
        if (!validateInput(productId, 'text')) {
            return res.status(400).json({ error: 'ID do produto inválido' });
        }
        
        const productsDb = await readDatabase('products.json');
        const product = productsDb.find(p => p.id === productId);
        
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        if (!product.filePath) {
            return res.status(404).json({ error: 'Arquivo do produto não encontrado' });
        }

        const userDb = await readDatabase('users.json');
        const user = userDb.users.find(u => u.id === req.user.id);
        
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        const hasPurchased = user.orders && user.orders.some(order => 
            order.productId === productId && order.status === 'completed'
        );

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

        const downloadsDb = await readDatabase('downloads.json');
        downloadsDb.downloads.push({
            productId: product.id,
            productName: product.name,
            userId: user.id,
            downloadedAt: new Date().toISOString(),
            ip: req.ip
        });
        await writeDatabase('downloads.json', downloadsDb);

        product.downloads = (product.downloads || 0) + 1;
        await writeDatabase('products.json', productsDb);

        await logActivity('PRODUCT_DOWNLOADED', `Produto baixado (autenticado): ${product.name}`, user.id, req.ip);

        const originalFileName = product.fileName || product.name.replace(/[^a-z0-9]/gi, '_') + path.extname(product.filePath);
        res.setHeader('Content-Disposition', `attachment; filename="${originalFileName}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.download(filePath, originalFileName);

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/verify-token', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await readDatabase('products.json');
        res.setHeader('Cache-Control', 'public, max-age=300');
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        if (!validateInput(id, 'text')) {
            return res.status(400).json({ error: 'ID inválido' });
        }
        
        const products = await readDatabase('products.json');
        const product = products.find(p => p.id === id);
        
        if (!product) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }
        
        res.setHeader('Cache-Control', 'public, max-age=300');
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/products/upcoming', async (req, res) => {
    try {
        const products = await readDatabase('products.json');
        const upcoming = products.filter(p => p.status === 'upcoming');
        res.setHeader('Cache-Control', 'public, max-age=300');
        res.json(upcoming);
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const stats = await readDatabase('stats.json');
        res.setHeader('Cache-Control', 'public, max-age=60');
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
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(currencies);
});

app.get('/api/payment-info/:currency', (req, res) => {
    const { currency } = req.params;
    
    if (!validateInput(currency, 'text')) {
        return res.status(400).json({ error: 'Moeda inválida' });
    }
    
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
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(info);
});

app.post('/api/calculate-crypto-price', async (req, res) => {
    try {
        const { usdAmount, cryptoCurrency } = req.body;
        
        if (!usdAmount || !cryptoCurrency) {
            return res.status(400).json({ error: 'Dados incompletos' });
        }
        
        if (!validateInput(cryptoCurrency, 'text')) {
            return res.status(400).json({ error: 'Moeda inválida' });
        }
        
        const usd = parseFloat(usdAmount);
        if (isNaN(usd) || usd <= 0 || usd > 1000000) {
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
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username e password são obrigatórios' });
        }
        
        if (!validateInput(username, 'username') || !validateInput(password, 'password')) {
            return res.status(400).json({ error: 'Dados inválidos' });
        }

        const isBlocked = await checkFailedAttempts(req.ip, username);
        if (isBlocked) {
            await logActivity('LOGIN_BLOCKED', `Tentativa de login bloqueada para IP: ${req.ip}`, null, req.ip);
            return res.status(403).json({ error: 'Acesso temporariamente bloqueado' });
        }

        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (!user) {
            await recordFailedAttempt(req.ip, username);
            await logActivity('LOGIN_FAILED', `Tentativa de login com usuário inexistente: ${username}`, null, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            await recordFailedAttempt(req.ip, username);
            await logActivity('LOGIN_FAILED', `Senha incorreta para usuário: ${username}`, user.id, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        if (!user.isAdmin) {
            await recordFailedAttempt(req.ip, username);
            await logActivity('LOGIN_FAILED', `Usuário não-admin tentou acessar admin: ${username}`, user.id, req.ip);
            return res.status(403).json({ error: 'Acesso não autorizado. Apenas administradores.' });
        }

        user.lastLogin = new Date().toISOString();
        user.lastActive = new Date().toISOString();
        await writeDatabase('users.json', db);

        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                email: user.email,
                isAdmin: user.isAdmin 
            },
            SECRET_KEY,
            { expiresIn: '8h' }
        );

        await logActivity('LOGIN_SUCCESS', `Admin ${username} fez login`, user.id, req.ip);

        res.setHeader('Authorization', `Bearer ${token}`);
        
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
            token,
            expiresIn: '8h'
        });

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

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
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

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
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/products', authenticateToken, async (req, res) => {
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
        
        if (!validateInput(productData.name, 'text') || !validateInput(productData.description, 'text')) {
            return res.status(400).json({ error: 'Dados do produto inválidos' });
        }

        const productsDb = await readDatabase('products.json');
        
        const newProduct = {
            id: `prod-${Date.now()}-${cryptoRandomString({length: 12, type: 'alphanumeric'})}`,
            name: validator.escape(productData.name.substring(0, 255)),
            description: validator.escape(productData.description.substring(0, 500)),
            longDescription: productData.longDescription ? validator.escape(productData.longDescription.substring(0, 5000)) : '',
            price: parseFloat(productData.price),
            originalPrice: parseFloat(productData.originalPrice || productData.price),
            currency: productData.currency || 'USD',
            category: validateInput(productData.category, 'text') ? productData.category : 'automation',
            features: productData.features ? (Array.isArray(productData.features) ? productData.features.map(f => validator.escape(f.substring(0, 100))) : productData.features.split(',').map(f => validator.escape(f.trim().substring(0, 100)))) : [],
            status: productData.isUpcoming ? 'upcoming' : 'active',
            featured: !!productData.featured,
            uploadDate: new Date().toISOString(),
            lastUpdate: new Date().toISOString(),
            version: validateInput(productData.version, 'text') ? productData.version : '1.0.0',
            downloads: 0,
            rating: 0,
            tags: productData.tags ? (Array.isArray(productData.tags) ? productData.tags.map(t => validator.escape(t.substring(0, 50))) : productData.tags.split(',').map(t => validator.escape(t.trim().substring(0, 50)))) : [],
            systemRequirements: productData.systemRequirements || {},
            includes: productData.includes ? (Array.isArray(productData.includes) ? productData.includes.map(i => validator.escape(i.substring(0, 100))) : productData.includes.split(',').map(i => validator.escape(i.trim().substring(0, 100)))) : [],
            fileSize: validateInput(productData.fileSize, 'text') ? productData.fileSize : '0 MB',
            filePath: validateInput(productData.fileUrl, 'text') ? productData.fileUrl : '',
            fileName: validateInput(productData.fileName, 'filename') ? productData.fileName : '',
            developer: validateInput(productData.developer, 'text') ? productData.developer : 'Lua Works Team',
            changelog: Array.isArray(productData.changelog) ? productData.changelog.map(c => validator.escape(c.substring(0, 500))) : []
        };

        productsDb.push(newProduct);
        await writeDatabase('products.json', productsDb);

        await logActivity('PRODUCT_ADDED', `Produto adicionado: ${newProduct.name}`, user.id, req.ip);

        res.status(201).json({
            message: 'Produto criado com sucesso!',
            product: newProduct
        });

    } catch (error) {
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
        
        const { id } = req.params;
        
        if (!validateInput(id, 'text')) {
            return res.status(400).json({ error: 'ID inválido' });
        }

        const productsDb = await readDatabase('products.json');
        const productIndex = productsDb.findIndex(p => p.id === id);
        
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

        await logActivity('PRODUCT_UPDATED', `Produto atualizado: ${updatedProduct.name}`, user.id, req.ip);

        res.json({
            message: 'Produto atualizado com sucesso!',
            product: updatedProduct
        });

    } catch (error) {
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
        
        const { id } = req.params;
        
        if (!validateInput(id, 'text')) {
            return res.status(400).json({ error: 'ID inválido' });
        }

        const productsDb = await readDatabase('products.json');
        const productIndex = productsDb.findIndex(p => p.id === id);
        
        if (productIndex === -1) {
            return res.status(404).json({ error: 'Produto não encontrado' });
        }

        const deletedProduct = productsDb[productIndex];
        
        if (deletedProduct.filePath) {
            const filePath = path.join(__dirname, deletedProduct.filePath);
            try {
                await fs.unlink(filePath);
                await logActivity('FILE_DELETED', `Arquivo removido: ${deletedProduct.filePath}`, user.id, req.ip);
            } catch (error) {
            }
        }

        productsDb.splice(productIndex, 1);
        await writeDatabase('products.json', productsDb);

        await logActivity('PRODUCT_DELETED', `Produto excluído: ${deletedProduct.name}`, user.id, req.ip);

        res.json({
            message: 'Produto excluído com sucesso!'
        });

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

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
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/api/admin/security-logs', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const logsDb = await readDatabase('logs.json');
        const securityLogs = logsDb.logs
            .filter(l => l.event.includes('LOGIN') || l.event.includes('SECURITY') || l.event.includes('FILE'))
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 20);

        res.json(securityLogs);

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/admin/reset-credentials', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
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
        
        if (!validateInput(username, 'username')) {
            return res.status(400).json({ error: 'Nome de usuário inválido' });
        }
        
        if (!validateInput(email, 'email')) {
            return res.status(400).json({ error: 'Email inválido' });
        }
        
        if (!validateInput(password, 'password')) {
            return res.status(400).json({ error: 'Senha inválida. Mínimo 8 caracteres com maiúsculas, minúsculas, números e símbolos.' });
        }

        const db = await readDatabase('users.json');
        
        if (db.users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }
        
        if (db.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
            return res.status(400).json({ error: 'Nome de usuário já existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        const newUser = {
            id: Date.now().toString() + '-' + cryptoRandomString({length: 8, type: 'alphanumeric'}),
            username: validator.escape(username),
            email: validator.normalizeEmail(email),
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
                currency: 'USD',
                notifications: true,
                newsletter: true,
                language: 'pt-BR'
            },
            orders: [],
            downloads: [],
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString(),
            lastActive: new Date().toISOString(),
            isAdmin: false,
            isVerified: false,
            twoFactorEnabled: false,
            apiKey: 'lw_' + crypto.randomBytes(32).toString('hex')
        };

        db.users.push(newUser);
        await writeDatabase('users.json', db);

        const stats = await readDatabase('stats.json');
        stats.totalUsers = db.users.length;
        stats.activeUsers = db.users.filter(u => u.lastLogin).length;
        await writeDatabase('stats.json', stats);

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

        await logActivity('USER_REGISTERED', `Novo usuário registrado: ${username}`, newUser.id, req.ip);

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
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }
        
        if (!validateInput(email, 'email') || !validateInput(password, 'password')) {
            return res.status(400).json({ error: 'Dados inválidos' });
        }

        const isBlocked = await checkFailedAttempts(req.ip, email);
        if (isBlocked) {
            await logActivity('LOGIN_BLOCKED', `Tentativa de login bloqueada para IP: ${req.ip}`, null, req.ip);
            return res.status(403).json({ error: 'Acesso temporariamente bloqueado' });
        }

        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
        
        if (!user) {
            await recordFailedAttempt(req.ip, email);
            await logActivity('LOGIN_FAILED', `Tentativa de login com email inexistente: ${email}`, null, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            await recordFailedAttempt(req.ip, email);
            await logActivity('LOGIN_FAILED', `Senha incorreta para email: ${email}`, user.id, req.ip);
            return res.status(401).json({ error: 'Credenciais inválidas' });
        }

        user.lastLogin = new Date().toISOString();
        user.lastActive = new Date().toISOString();
        await writeDatabase('users.json', db);

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

        res.setHeader('Authorization', `Bearer ${token}`);
        
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

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

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
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

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
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

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
            features: p.features?.slice(0, 3) || [],
            status: p.status,
            featured: p.featured,
            uploadDate: p.uploadDate,
            version: p.version,
            downloads: p.downloads || 0,
            rating: p.rating || 0,
            tags: p.tags || []
        }));
        
        res.setHeader('Cache-Control', 'public, max-age=300');
        res.json(publicProducts);
    } catch (error) {
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
        
        res.setHeader('Cache-Control', 'public, max-age=300');
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
        
        if (!validateInput(txHash, 'text') || !validateInput(currency, 'text') || !validateInput(productId, 'text')) {
            return res.status(400).json({ error: 'Dados inválidos' });
        }

        await logActivity('PAYMENT_VERIFICATION_ATTEMPT', 
            `Tentativa de verificação: ${currency} ${amount} - TX: ${txHash.substring(0, 20)}...`, 
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
        const db = await readDatabase('users.json');
        const user = db.users.find(u => u.id === req.user.id);
        
        if (!user || !user.isAdmin) {
            return res.status(403).json({ error: 'Acesso negado' });
        }

        const backupDir = path.join(__dirname, 'backups');
        await fs.mkdir(backupDir, { recursive: true });
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = path.join(backupDir, `backup-${timestamp}.zip`);
        const archiver = require('archiver');
        const output = fsSync.createWriteStream(backupFile);
        const archive = archiver('zip', { zlib: { level: 9 } });
        
        output.on('close', () => {
            res.setHeader('Content-Type', 'application/zip');
            res.setHeader('Content-Disposition', `attachment; filename="lua-works-backup-${timestamp}.zip"`);
            res.download(backupFile, (err) => {
                if (err) {
                }
                fs.unlink(backupFile).catch(() => {});
            });
        });
        
        archive.pipe(output);
        archive.directory(DB_PATH, 'database');
        archive.directory(UPLOADS_PATH, 'uploads');
        archive.finalize();

    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor' });
    }
});

app.get('/admin', (req, res) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
    res.sendFile(path.join(__dirname, '/public/admin-login.html'));
});

app.get('/admin/dashboard', (req, res) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
    res.sendFile(path.join(__dirname, '/public/admin-dashboard.html'));
});

app.get('*', (req, res) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.sendFile(path.join(PUBLIC_PATH, 'index.html'));
});

async function startServer() {
    try {
        await fs.mkdir(DB_PATH, { recursive: true });
        await fs.mkdir(UPLOADS_PATH, { recursive: true });
        await fs.mkdir(PUBLIC_PATH, { recursive: true });
        await fs.mkdir(path.join(__dirname, 'backups'), { recursive: true });
        
        const files = ['users.json', 'products.json', 'orders.json', 'stats.json', 'downloads.json', 'reviews.json', 'logs.json', 'security.json'];
        for (const file of files) {
            try {
                await fs.access(path.join(DB_PATH, file));
            } catch {
                if (file === 'users.json') await writeDatabase(file, { users: [] });
                else if (file === 'products.json') await writeDatabase(file, [] );
                else if (file === 'orders.json') await writeDatabase(file, { orders: [] });
                else if (file === 'stats.json') await writeDatabase(file, await generateRealStats());
                else if (file === 'downloads.json') await writeDatabase(file, { downloads: [] });
                else if (file === 'reviews.json') await writeDatabase(file, { reviews: [] });
                else if (file === 'logs.json') await writeDatabase(file, { logs: [] });
                else if (file === 'security.json') await writeDatabase(file, { failedAttempts: [], blockedIPs: [] });
            }
        }

        await syncAdminUser();

        app.listen(PORT, () => {
        });
    } catch (error) {
        process.exit(1);
    }
}

startServer().catch(() => {});
