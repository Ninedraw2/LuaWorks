const API_BASE = '/api';
let products = [];
let upcomingProducts = [];
let currencies = [];
let selectedProduct = null;
let selectedCurrency = null;
let currentUser = null;
let userPurchases = [];
let cart = [];
let isCheckoutModal = false;
let adminEnabled = false;
let adminSequence = [];
const adminPassword = ['ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight', 'KeyB', 'KeyA'];

const sampleProducts = [
    {
        id: 'auto-farm-1',
        name: 'Auto Farm Supreme',
        description: 'Sistema de farm automático com anti-ban avançado',
        category: 'automation',
        price: '0.005',
        currency: 'BTC',
        originalPrice: '0.008',
        discount: 37,
        rating: 4.8,
        downloads: 124,
        version: '2.1',
        fileSize: '15KB',
        features: ['Anti-ban system', 'Multi-threaded', 'Auto-update', 'GUI configurável'],
        uploadDate: '2024-01-15',
        featured: true,
        status: 'available'
    },
    {
        id: 'bot-system-1',
        name: 'Bot Manager Pro',
        description: 'Gerenciador de múltiplos bots simultâneos',
        category: 'bot',
        price: '0.008',
        currency: 'BTC',
        rating: 4.5,
        downloads: 89,
        version: '1.3',
        fileSize: '25KB',
        features: ['Multi-account', 'Proxy support', 'Task scheduler', 'Log system'],
        uploadDate: '2024-01-10',
        status: 'available'
    },
    {
        id: 'sys-optimizer',
        name: 'System Optimizer',
        description: 'Otimizador de performance para scripts Lua',
        category: 'system',
        price: '0.003',
        currency: 'BTC',
        rating: 4.9,
        downloads: 210,
        version: '3.0',
        fileSize: '8KB',
        features: ['FPS boost', 'Memory optimizer', 'Cache system', 'Error handler'],
        uploadDate: '2024-01-05',
        status: 'available'
    },
    {
        id: 'utility-pack',
        name: 'Utility Pack Deluxe',
        description: 'Coleção de utilitários para desenvolvimento',
        category: 'utility',
        price: '0.006',
        currency: 'BTC',
        originalPrice: '0.010',
        discount: 40,
        rating: 4.7,
        downloads: 156,
        version: '1.5',
        fileSize: '30KB',
        features: ['Debug tools', 'Code formatter', 'Library manager', 'Template system'],
        uploadDate: '2024-01-12',
        featured: true,
        status: 'available'
    },
    {
        id: 'security-suite',
        name: 'Security Suite Pro',
        description: 'Pacote completo de segurança para scripts',
        category: 'tool',
        price: '0.009',
        currency: 'BTC',
        rating: 4.6,
        downloads: 78,
        version: '2.2',
        fileSize: '20KB',
        features: ['Encryption', 'Obfuscation', 'License system', 'Anti-tamper'],
        uploadDate: '2024-01-08',
        status: 'available'
    },
    {
        id: 'ai-assistant',
        name: 'AI Assistant Beta',
        description: 'Assistente de IA para desenvolvimento Lua',
        category: 'automation',
        price: '0.012',
        currency: 'BTC',
        rating: 4.4,
        downloads: 45,
        version: '0.9',
        fileSize: '50KB',
        features: ['Code suggestions', 'Error detection', 'Auto-complete', 'Learning system'],
        uploadDate: '2024-01-18',
        status: 'available'
    }
];

const sampleUpcoming = [];

document.addEventListener('DOMContentLoaded', async () => {
    console.log('Lua Works - Inicializando sistema...');
    
    try {
        await loadAllData();
        await loadUserData();
        loadCart();
        setupEventListeners();
        setupAnimations();
        setupAdminSystem();
        updateUI();
        renderProducts();
        renderCurrencies();
        updateStatsDisplay();
        console.log('Sistema inicializado com sucesso!');
    } catch (error) {
        console.error('Erro na inicialização:', error);
        showError('Erro ao carregar o sistema. Recarregue a página.');
    }
});

async function loadAllData() {
    try {
        const [productsData, currenciesData, upcomingData] = await Promise.all([
            fetchData('/products'),
            fetchData('/currencies'),
            fetchData('/products/upcoming')
        ]);
        
        products = productsData || sampleProducts;
        currencies = currenciesData || getDefaultCurrencies();
        upcomingProducts = upcomingData || sampleUpcoming;
    } catch (error) {
        console.warn('Erro ao carregar dados da API, usando dados locais:', error.message);
        products = sampleProducts;
        currencies = getDefaultCurrencies();
        upcomingProducts = sampleUpcoming;
    }
}

async function loadUserData() {
    const token = localStorage.getItem('auth_token');
    const userData = localStorage.getItem('user_data');
    
    if (!token || !userData) return;
    
    try {
        currentUser = JSON.parse(userData);
        userPurchases = JSON.parse(localStorage.getItem('user_purchases') || '[]');
        if (currentUser.email === 'admin@luaworks.dev' || currentUser.username === 'admin' || currentUser.isAdmin) {
            currentUser.isAdmin = true;
        }
        console.log(`Usuário carregado: ${currentUser.username} ${currentUser.isAdmin ? '(Admin)' : ''}`);
        console.log(`Compras carregadas: ${userPurchases.length}`);
    } catch (error) {
        console.error('Erro ao carregar dados do usuário:', error);
        logoutUser();
    }
}

function loadCart() {
    const savedCart = localStorage.getItem('cart');
    if (savedCart) {
        try {
            cart = JSON.parse(savedCart);
            updateCartCount();
        } catch (error) {
            console.error('Erro ao carregar carrinho:', error);
            cart = [];
        }
    }
}

function saveCart() {
    localStorage.setItem('cart', JSON.stringify(cart));
    updateCartCount();
}

function updateCartCount() {
    const cartCount = document.getElementById('cartCount');
    if (cartCount) {
        const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
        cartCount.textContent = totalItems;
        if (totalItems > 0) {
            cartCount.style.display = 'flex';
        } else {
            cartCount.style.display = 'none';
        }
    }
}

async function fetchData(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.warn(`Não foi possível carregar ${endpoint}:`, error.message);
        return null;
    }
}

function getDefaultCurrencies() {
    return [
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
        }
    ];
}

function addToCart(productId) {
    const product = products.find(p => p.id === productId);
    if (!product) return;
    const existingItem = cart.find(item => item.productId === productId);
    if (existingItem) {
        existingItem.quantity += 1;
    } else {
        cart.push({
            productId: product.id,
            name: product.name,
            price: parseFloat(product.price),
            currency: product.currency,
            quantity: 1,
            image: getProductIcon(product.category)
        });
    }
    saveCart();
    updateCartModal();
    showMessage('Produto adicionado ao carrinho!', 'success');
    updateProductButton(productId, true);
}

function removeFromCart(productId) {
    const itemIndex = cart.findIndex(item => item.productId === productId);
    if (itemIndex !== -1) {
        cart.splice(itemIndex, 1);
        saveCart();
        updateCartModal();
        showMessage('Produto removido do carrinho', 'info');
        updateProductButton(productId, false);
    }
}

function updateCartModal() {
    const cartItems = document.getElementById('cartItems');
    const cartSummary = document.getElementById('cartSummary');
    const checkoutBtn = document.getElementById('checkoutBtn');
    const cartEmpty = cartItems.querySelector('.cart-empty');
    if (cart.length === 0) {
        if (cartEmpty) {
            cartEmpty.style.display = 'block';
        }
        cartSummary.style.display = 'none';
        checkoutBtn.style.display = 'none';
        const existingItems = cartItems.querySelectorAll('.cart-item');
        existingItems.forEach(item => item.remove());
    } else {
        if (cartEmpty) {
            cartEmpty.style.display = 'none';
        }
        const existingItems = cartItems.querySelectorAll('.cart-item');
        existingItems.forEach(item => item.remove());
        cart.forEach(item => {
            const cartItem = document.createElement('div');
            cartItem.className = 'cart-item';
            cartItem.innerHTML = `
                <div class="cart-item-image">
                    <i class="${item.image}"></i>
                </div>
                <div class="cart-item-info">
                    <div class="cart-item-title">${escapeHtml(item.name)}</div>
                    <div class="cart-item-price">${item.price} ${item.currency} × ${item.quantity}</div>
                </div>
                <button class="remove-from-cart" onclick="removeFromCart('${item.productId}')">
                    <i class="fas fa-trash"></i>
                </button>
            `;
            cartItems.appendChild(cartItem);
        });
        updateCartSummary();
        cartSummary.style.display = 'block';
        checkoutBtn.style.display = 'block';
    }
}

function updateCartSummary() {
    const subtotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const fee = subtotal * 0.02;
    const total = subtotal + fee;
    document.getElementById('cartSubtotal').textContent = `${subtotal.toFixed(4)} BTC`;
    document.getElementById('cartFee').textContent = `${fee.toFixed(4)} BTC`;
    document.getElementById('cartTotal').textContent = `${total.toFixed(4)} BTC`;
}

function updateProductButton(productId, inCart) {
    const productCard = document.querySelector(`.product-card[data-id="${productId}"]`);
    if (productCard) {
        const addToCartBtn = productCard.querySelector('.add-to-cart-btn');
        if (addToCartBtn) {
        }
    }
}

function renderProducts() {
    const container = document.getElementById('productsGrid');
    if (!container) return;
    let allProducts = [...products];
    if (upcomingProducts.length > 0) {
        allProducts = [...products, ...upcomingProducts];
    }
    container.innerHTML = allProducts.map(product => {
        const isUpcoming = product.status === 'upcoming';
        const isFeatured = product.featured;
        const hasPurchased = userPurchases.some(p => p.productId === product.id);
        const inCart = cart.some(item => item.productId === product.id);
        return `
            <div class="product-card fade-in" data-id="${product.id}" data-category="${product.category || 'automation'}" data-upcoming="${isUpcoming}">
                ${isFeatured ? '<div class="product-badge featured">DESTAQUE</div>' : ''}
                ${isUpcoming ? '<div class="product-badge upcoming">EM BREVE</div>' : ''}
                ${hasPurchased ? '<div class="product-badge purchased"><i class="fas fa-check-circle"></i> COMPRADO</div>' : ''}
                <div class="product-image" style="background: linear-gradient(135deg, ${getCategoryColor(product.category)}, rgba(0, 255, 136, 0.2));">
                    <i class="${getProductIcon(product.category)}"></i>
                    ${isUpcoming ? '<div class="upcoming-overlay"><i class="fas fa-clock"></i></div>' : ''}
                    ${hasPurchased ? '<div class="purchased-overlay"><i class="fas fa-download"></i> DISPONÍVEL</div>' : ''}
                </div>
                <div class="product-content">
                    <h3 class="product-title">${escapeHtml(product.name)}</h3>
                    <p class="product-description">${escapeHtml(product.description || 'Script Lua premium otimizado')}</p>
                    <div class="product-meta">
                        <span class="product-category ${product.category || 'automation'}">
                            <i class="${getCategoryIcon(product.category)}"></i> ${getCategoryName(product.category)}
                        </span>
                        <div class="product-rating">
                            ${renderStars(product.rating || 0)}
                            <span class="rating-text">${product.rating || 'N/A'}</span>
                        </div>
                    </div>
                    <div class="product-stats">
                        <span class="product-stat">
                            <i class="fas fa-download"></i> ${product.downloads || 0}
                        </span>
                        <span class="product-stat">
                            <i class="fas fa-code-branch"></i> v${product.version || '1.0'}
                        </span>
                        <span class="product-stat">
                            <i class="fas fa-hdd"></i> ${product.fileSize || 'N/A'}
                        </span>
                    </div>
                    <div class="product-price-container">
                        <div class="product-price">
                            ${escapeHtml(product.price)} <span class="currency-symbol">${product.currency || 'BTC'}</span>
                            ${product.originalPrice ? `<span class="original-price">${product.originalPrice} ${product.currency}</span>` : ''}
                        </div>
                        ${product.discount ? `<span class="product-discount">-${product.discount}%</span>` : ''}
                    </div>
                    <div class="product-features">
                        ${(product.features || []).slice(0, 3).map(feature => `
                            <span class="product-feature">
                                <i class="fas fa-check-circle"></i> ${escapeHtml(feature)}
                            </span>
                        `).join('')}
                    </div>
                    <div class="product-footer">
                        <div class="product-date">
                            <i class="fas fa-calendar"></i> ${formatDate(product.uploadDate || new Date().toISOString())}
                        </div>
                        <div class="product-actions">
                            ${hasPurchased ? `
                                <button class="btn btn-success" onclick="downloadProduct('${product.id}')">
                                    <i class="fas fa-download"></i> BAIXAR
                                </button>
                            ` : isUpcoming ? `
                                <button class="btn btn-secondary" disabled>
                                    <i class="fas fa-clock"></i> EM BREVE
                                </button>
                            ` : `
                                </button>
                                <button class="btn btn-info" onclick="viewProductDetails('${product.id}')">
                                    <i class="fas fa-info-circle"></i> DETALHES
                                </button>
                            `}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
    const loadingProducts = container.querySelector('.loading-products');
    if (loadingProducts) {
        loadingProducts.remove();
    }
}

function renderStars(rating) {
    const stars = [];
    const fullStars = Math.floor(rating);
    const hasHalfStar = rating % 1 >= 0.5;
    for (let i = 1; i <= 5; i++) {
        if (i <= fullStars) {
            stars.push('<i class="fas fa-star"></i>');
        } else if (i === fullStars + 1 && hasHalfStar) {
            stars.push('<i class="fas fa-star-half-alt"></i>');
        } else {
            stars.push('<i class="far fa-star"></i>');
        }
    }
    return stars.join('');
}

function renderCurrencies() {
    const container = document.getElementById('currenciesGrid');
    if (!container) return;
    container.innerHTML = currencies.map(currency => `
        <div class="currency-option" data-currency="${currency.id}" onclick="selectCurrency('${currency.id}')">
            <div class="currency-icon ${currency.id}" style="color: ${currency.color || '#00ff88'}">
                <i class="${currency.icon}"></i>
            </div>
            <h4>${currency.name}</h4>
            <p class="currency-symbol">${currency.symbol}</p>
            <p class="currency-network">${currency.network || 'Network'}</p>
            <div class="currency-selector">
                <div class="checkmark">
                    <i class="fas fa-check"></i>
                </div>
            </div>
        </div>
    `).join('');
}

function updateStatsDisplay() {
    const statsContainer = document.getElementById('statsContainer');
    if (statsContainer) {
        const totalProducts = products.length + upcomingProducts.length;
        const availableProducts = products.length;
        statsContainer.innerHTML = `
            <div class="hero-stats">
                <div class="stat-item">
                    <div class="stat-number">${availableProducts}</div>
                    <div class="stat-label">Scripts Ativos</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">${upcomingProducts.length}</div>
                    <div class="stat-label">Em Breve</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">${totalProducts}</div>
                    <div class="stat-label">Total</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">Beta</div>
                    <div class="stat-label">Status</div>
                </div>
            </div>
        `;
    }
}

function openPaymentModal(productId = null) {
    isCheckoutModal = productId === null;
    if (!isCheckoutModal) {
        selectedProduct = [...products, ...upcomingProducts].find(p => p.id === productId);
        if (!selectedProduct) {
            showError('Produto não encontrado');
            return;
        }
        if (selectedProduct.status === 'upcoming') {
            showMessage('Este produto estará disponível em breve!', 'info');
            return;
        }
        if (userPurchases.some(p => p.productId === productId)) {
            showMessage('Você já possui este produto! Acesse Minhas Compras.', 'success');
            return;
        }
    } else {
        if (cart.length === 0) {
            showError('Seu carrinho está vazio');
            return;
        }
        const subtotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        const fee = subtotal * 0.02;
        const total = subtotal + fee;
        selectedProduct = {
            id: 'cart-checkout',
            name: 'Carrinho de Compras',
            description: `Compra de ${cart.length} produto(s)`,
            price: total.toFixed(4),
            currency: 'BTC',
            features: cart.map(item => `${item.quantity}x ${item.name}`)
        };
    }
    const modal = document.getElementById('paymentModal');
    const productName = document.getElementById('modalProductName');
    const productPrice = document.getElementById('modalProductPrice');
    const productDescription = document.getElementById('modalProductDescription');
    const productFeatures = document.getElementById('modalProductFeatures');
    if (!productName || !productPrice || !productDescription || !productFeatures) {
        showError('Elementos do modal não encontrados');
        return;
    }
    productName.textContent = selectedProduct.name;
    productPrice.innerHTML = `
        <span class="price-main">${selectedProduct.price} ${selectedProduct.currency || 'BTC'}</span>
    `;
    productDescription.textContent = selectedProduct.description;
    productFeatures.innerHTML = (selectedProduct.features || []).map(feature => `
        <li><i class="fas fa-check"></i> ${escapeHtml(feature)}</li>
    `).join('');
    selectedCurrency = null;
    resetCurrencySelection();
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            modalContent.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
        }
    }, 10);
    console.log(`Abrindo modal para: ${selectedProduct.name}`);
}

function closePaymentModal() {
    const modal = document.getElementById('paymentModal');
    const modalContent = modal.querySelector('.modal-content');
    if (modalContent) {
        modalContent.style.opacity = '0';
        modalContent.style.transform = 'translateY(-50px)';
    }
    setTimeout(() => {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
        selectedProduct = null;
        selectedCurrency = null;
        isCheckoutModal = false;
    }, 300);
    console.log('Modal fechado');
}

function selectCurrency(currencyId) {
    selectedCurrency = currencies.find(c => c.id === currencyId);
    if (!selectedCurrency) return;
    document.querySelectorAll('.currency-option').forEach(option => {
        option.classList.remove('selected');
    });
    const selectedOption = document.querySelector(`[data-currency="${currencyId}"]`);
    if (selectedOption) {
        selectedOption.classList.add('selected');
    }
    updateWalletAddress();
    updateQRCode();
    console.log(`Moeda selecionada: ${selectedCurrency.name}`);
}

function updateWalletAddress() {
    if (!selectedCurrency) return;
    const addressElement = document.getElementById('walletAddress');
    const networkElement = document.getElementById('walletNetwork');
    if (addressElement) {
        addressElement.textContent = selectedCurrency.address;
        addressElement.style.color = selectedCurrency.color || '#00ff88';
    }
    if (networkElement) {
        networkElement.textContent = `Rede: ${selectedCurrency.network || 'Mainnet'}`;
    }
}

function updateQRCode() {
    if (!selectedCurrency) return;
    const qrElement = document.getElementById('walletQr');
    if (!qrElement) return;
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(selectedCurrency.address)}`;
    qrElement.innerHTML = `
        <div class="qr-container">
            <img src="${qrCodeUrl}" alt="QR Code para ${selectedCurrency.name}" class="qr-image">
            <div class="qr-info">
                <div class="qr-currency">
                    <i class="${selectedCurrency.icon}" style="color: ${selectedCurrency.color}"></i>
                    <span>${selectedCurrency.name} (${selectedCurrency.symbol})</span>
                </div>
                <div class="qr-network">${selectedCurrency.network || 'Network'}</div>
            </div>
        </div>
    `;
}

function resetCurrencySelection() {
    selectedCurrency = null;
    document.querySelectorAll('.currency-option').forEach(option => {
        option.classList.remove('selected');
    });
    const addressElement = document.getElementById('walletAddress');
    if (addressElement) {
        addressElement.textContent = 'Selecione uma moeda acima';
        addressElement.style.color = '';
    }
    const networkElement = document.getElementById('walletNetwork');
    if (networkElement) {
        networkElement.textContent = '';
    }
    const qrElement = document.getElementById('walletQr');
    if (qrElement) {
        qrElement.innerHTML = '<div class="qr-placeholder"><i class="fas fa-qrcode"></i><p>Selecione uma moeda</p></div>';
    }
}

async function confirmPayment() {
    if (!selectedProduct) {
        showError('Nenhum produto selecionado');
        return;
    }
    if (!selectedCurrency) {
        showError('Selecione uma moeda para pagamento');
        return;
    }
    const token = localStorage.getItem('auth_token');
    if (!token) {
        showError('Você precisa estar logado para realizar a compra');
        openLoginModal();
        return;
    }
    const btn = document.getElementById('confirmPaymentBtn');
    if (!btn) return;
    const originalText = btn.innerHTML;
    const originalBg = btn.style.background;
    try {
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> PROCESSANDO PAGAMENTO...';
        btn.disabled = true;
        btn.style.background = 'linear-gradient(45deg, #666, #888)';
        await new Promise(resolve => setTimeout(resolve, 2000));
        if (isCheckoutModal) {
            await processCartCheckout();
        } else {
            await processSinglePurchase();
        }
    } catch (error) {
        console.error('Erro no pagamento:', error);
        showPaymentError(error);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
        btn.style.background = originalBg;
    }
}

async function processSinglePurchase() {
    const orderId = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    const licenseKey = 'LUA-' + Math.random().toString(36).substr(2, 12).toUpperCase();
    const newPurchase = {
        id: orderId,
        productId: selectedProduct.id,
        productName: selectedProduct.name,
        licenseKey: licenseKey,
        amount: parseFloat(selectedProduct.price),
        currency: selectedCurrency.symbol,
        status: 'completed',
        date: new Date().toISOString(),
        items: [{
            productId: selectedProduct.id,
            name: selectedProduct.name,
            price: parseFloat(selectedProduct.price),
            quantity: 1
        }],
        subtotal: parseFloat(selectedProduct.price),
        fee: parseFloat(selectedProduct.price) * 0.02,
        total: parseFloat(selectedProduct.price) * 1.02
    };
    userPurchases.push(newPurchase);
    localStorage.setItem('user_purchases', JSON.stringify(userPurchases));
    showPaymentSuccess({
        order: newPurchase
    });
}

async function processCartCheckout() {
    const orderId = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    const subtotal = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    const fee = subtotal * 0.02;
    const total = subtotal + fee;
    const newPurchase = {
        id: orderId,
        productId: 'cart-checkout',
        productName: 'Carrinho de Compras',
        licenseKey: null,
        amount: total,
        currency: 'BTC',
        status: 'completed',
        date: new Date().toISOString(),
        items: cart.map(item => ({
            productId: item.productId,
            name: item.name,
            price: item.price,
            quantity: item.quantity,
            licenseKey: 'LUA-' + Math.random().toString(36).substr(2, 12).toUpperCase()
        })),
        subtotal: subtotal,
        fee: fee,
        total: total
    };
    newPurchase.items.forEach(item => {
        const productPurchase = {
            id: 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase(),
            productId: item.productId,
            productName: item.name,
            licenseKey: item.licenseKey,
            amount: item.price * item.quantity,
            currency: 'BTC',
            status: 'completed',
            date: new Date().toISOString(),
            items: [{
                productId: item.productId,
                name: item.name,
                price: item.price,
                quantity: item.quantity
            }],
            subtotal: item.price * item.quantity,
            fee: (item.price * item.quantity) * 0.02,
            total: (item.price * item.quantity) * 1.02
        };
        userPurchases.push(productPurchase);
    });
    localStorage.setItem('user_purchases', JSON.stringify(userPurchases));
    cart = [];
    saveCart();
    updateCartModal();
    showPaymentSuccess({
        order: newPurchase
    });
}

function showPaymentSuccess(paymentData) {
    closePaymentModal();
    showMessage('Pagamento confirmado! Suas compras estão disponíveis.', 'success');
    setTimeout(() => {
        let receipt = `COMPRA REALIZADA COM SUCESSO!\n\n`;
        if (isCheckoutModal) {
            receipt += `Produto: Carrinho de Compras\n`;
            receipt += `Itens: ${paymentData.order.items.length}\n`;
            paymentData.order.items.forEach((item, index) => {
                receipt += `  ${index + 1}. ${item.quantity}x ${item.name}\n`;
                receipt += `     Chave: ${item.licenseKey}\n`;
            });
        } else {
            receipt += `Produto: ${selectedProduct.name}\n`;
            receipt += `Chave de Licença: ${paymentData.order.licenseKey}\n`;
        }
        receipt += `\nValor: ${paymentData.order.total.toFixed(4)} ${paymentData.order.currency}\n`;
        receipt += `ID do Pedido: ${paymentData.order.id}\n`;
        receipt += `Data: ${formatDate(paymentData.order.date)}\n\n`;
        receipt += `IMPORTANTE:\n`;
        receipt += `• Guarde as chaves de licença\n`;
        receipt += `• Os downloads estarão disponíveis por tempo ilimitado\n`;
        receipt += `• Suporte via Discord: discord.gg/luaworks\n\n`;
        receipt += `Obrigado por comprar na Lua Works!`;
        alert(receipt);
        renderProducts();
        updateUI();
    }, 500);
}

function showPaymentError(error) {
    showMessage(`Erro no pagamento: ${error.message}`, 'error');
    setTimeout(() => {
        if (confirm('Houve um erro no processamento. Deseja tentar novamente ou entrar em contato com o suporte?')) {
            openPaymentModal(isCheckoutModal ? null : selectedProduct?.id);
        }
    }, 1000);
}

async function downloadProduct(productId) {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        showError('Você precisa estar logado para baixar');
        openLoginModal();
        return;
    }
    const purchase = userPurchases.find(p => p.productId === productId);
    if (!purchase) {
        showError('Você não possui este produto');
        return;
    }
    try {
        await downloadFromServer(productId, token);
    } catch (error) {
        try {
            const response = await fetch(`/api/download/${productId}`);
            if (response.ok) {
                window.open(`/api/download/${productId}`, '_blank');
            } else {
                throw new Error('Download não disponível');
            }
        } catch (fallbackError) {
            console.error('Erro no fallback:', fallbackError);
        }
    }
}

async function downloadFromServer(productId, token) {
    try {
        showMessage('Iniciando download...', 'info');
        const response = await fetch(`/api/download/${productId}/authenticated`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || `Erro HTTP ${response.status}`);
        }
        let filename = 'download.lua';
        const contentDisposition = response.headers.get('Content-Disposition');
        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename="(.+)"/);
            if (filenameMatch) {
                filename = filenameMatch[1];
            }
        }
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        registerDownload(filename, productId);
        showMessage('Download iniciado com sucesso!', 'success');
    } catch (error) {
        console.error('Erro no download do servidor:', error);
        throw error;
    }
}

function registerDownload(filename, productId) {
    const downloadHistory = JSON.parse(localStorage.getItem('download_history') || '[]');
    downloadHistory.push({
        filename: filename,
        timestamp: new Date().toISOString(),
        productId: productId
    });
    localStorage.setItem('download_history', JSON.stringify(downloadHistory));
}

async function loginUser(email, password) {
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Erro no login');
        }
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('user_data', JSON.stringify(data.user));
        localStorage.setItem('user_purchases', JSON.stringify(data.user.orders || []));
        currentUser = data.user;
        userPurchases = data.user.orders || [];
        updateUI();
        showMessage('Login realizado com sucesso!', 'success');
        return { success: true, user: data.user };
    } catch (error) {
        console.error('Erro no login:', error);
        showError(error.message);
        return { success: false, error: error.message };
    }
}

async function registerUser(username, email, password) {
    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Erro no registro');
        }
        localStorage.setItem('auth_token', data.token);
        localStorage.setItem('user_data', JSON.stringify(data.user));
        localStorage.setItem('user_purchases', '[]');
        currentUser = data.user;
        userPurchases = [];
        updateUI();
        showMessage('Conta criada com sucesso! Bem-vindo!', 'success');
        return { success: true, user: data.user };
    } catch (error) {
        console.error('Erro no registro:', error);
        showError(error.message);
        return { success: false, error: error.message };
    }
}

function logoutUser() {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_data');
    localStorage.removeItem('user_purchases');
    currentUser = null;
    userPurchases = [];
    updateUI();
    showMessage('Logout realizado com sucesso!', 'info');
}

function setupEventListeners() {
    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (modal && modal.id === 'paymentModal') {
                closePaymentModal();
            } else if (modal && modal.id === 'downloadModal') {
                closeDownloadModal();
            } else if (modal) {
                closeModal(modal.id);
            }
        });
    });
    document.getElementById('paymentModal')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
            closePaymentModal();
        }
    });
    const confirmBtn = document.getElementById('confirmPaymentBtn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', confirmPayment);
    }
    window.copyWalletAddress = function() {
        const address = document.getElementById('walletAddress')?.textContent;
        if (!address || address === 'Selecione uma moeda acima') {
            showError('Selecione uma moeda primeiro');
            return;
        }
        navigator.clipboard.writeText(address).then(() => {
            showMessage('Endereço copiado para a área de transferência!', 'success');
            const copyBtn = document.querySelector('.copy-btn');
            if (copyBtn) {
                const originalText = copyBtn.innerHTML;
                copyBtn.innerHTML = '<i class="fas fa-check"></i> Copiado!';
                copyBtn.style.background = 'var(--success)';
                copyBtn.style.color = 'var(--darker-bg)';
                setTimeout(() => {
                    copyBtn.innerHTML = originalText;
                    copyBtn.style.background = '';
                    copyBtn.style.color = '';
                }, 2000);
            }
        }).catch(err => {
            console.error('Erro ao copiar:', err);
            const textArea = document.createElement('textarea');
            textArea.value = address;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            showMessage('Endereço copiado!', 'success');
        });
    };
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            const filter = this.dataset.filter;
            filterProducts(filter);
        });
    });
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', toggleMobileMenu);
    }
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                toggleMobileMenu();
            }
        });
    });
    window.addEventListener('resize', () => {
        const navLinks = document.querySelector('.nav-links');
        if (window.innerWidth > 768 && navLinks && navLinks.style.display === 'flex') {
            navLinks.style.display = '';
            const menuBtn = document.querySelector('.mobile-menu-btn i');
            if (menuBtn) {
                menuBtn.className = 'fas fa-bars';
            }
        }
    });
    document.getElementById('loginBtn')?.addEventListener('click', openLoginModal);
    document.getElementById('registerBtn')?.addEventListener('click', openRegisterModal);
    document.getElementById('logoutBtn')?.addEventListener('click', logoutUser);
    document.getElementById('cartBtn')?.addEventListener('click', toggleCartModal);
    document.querySelectorAll('.close-cart').forEach(btn => {
        btn.addEventListener('click', closeCartModal);
    });
    document.getElementById('checkoutBtn')?.addEventListener('click', function() {
        closeCartModal();
        openPaymentModal();
    });
}

function toggleCartModal() {
    const cartModal = document.getElementById('cartModal');
    cartModal.classList.toggle('active');
    document.body.style.overflow = cartModal.classList.contains('active') ? 'hidden' : 'auto';
    if (cartModal.classList.contains('active')) {
        updateCartModal();
    }
}

function closeCartModal() {
    const cartModal = document.getElementById('cartModal');
    cartModal.classList.remove('active');
    document.body.style.overflow = 'auto';
}

function setupAnimations() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });
    document.querySelectorAll('.product-card, .feature-card, .expertise-item, .stat-card').forEach(el => {
        observer.observe(el);
    });
}

function filterProducts(filter) {
    const productCards = document.querySelectorAll('.product-card');
    const noResults = document.getElementById('noResults');
    let visibleCount = 0;
    productCards.forEach(card => {
        const isUpcoming = card.dataset.upcoming === 'true';
        const category = card.dataset.category;
        const productId = card.dataset.id;
        let show = false;
        switch(filter) {
            case 'all':
                show = true;
                break;
            case 'upcoming':
                show = isUpcoming;
                break;
            case 'purchased':
                show = userPurchases.some(p => p.productId === productId);
                break;
            default:
                show = category === filter && !isUpcoming;
                break;
        }
        if (show) {
            card.style.display = 'block';
            visibleCount++;
            card.style.animationDelay = `${visibleCount * 0.05}s`;
        } else {
            card.style.display = 'none';
        }
    });
    if (noResults) {
        if (visibleCount === 0) {
            noResults.style.display = 'block';
        } else {
            noResults.style.display = 'none';
        }
    }
    console.log(`Filtro "${filter}" aplicado: ${visibleCount} produtos visíveis`);
}

function toggleMobileMenu() {
    const navLinks = document.querySelector('.nav-links');
    const menuBtn = document.querySelector('.mobile-menu-btn i');
    if (!navLinks || !menuBtn) return;
    if (navLinks.style.display === 'flex') {
        navLinks.style.display = 'none';
        menuBtn.className = 'fas fa-bars';
    } else {
        navLinks.style.display = 'flex';
        menuBtn.className = 'fas fa-times';
    }
}

function updateUI() {
    const loginBtn = document.getElementById('loginBtn');
    const registerBtn = document.getElementById('registerBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const userMenu = document.getElementById('userMenu');
    if (currentUser) {
        if (loginBtn) loginBtn.style.display = 'none';
        if (registerBtn) registerBtn.style.display = 'none';
        if (logoutBtn) logoutBtn.style.display = 'block';
        if (userMenu) {
            userMenu.innerHTML = `
                <div class="user-info">
                    <img src="${currentUser.profile?.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(currentUser.username)}&background=00ff88&color=000&bold=true&size=256`}" alt="${currentUser.username}" class="user-avatar">
                    <span class="username">${currentUser.username}</span>
                    ${currentUser.isAdmin ? '<span class="admin-badge" style="background: #ff3366; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.7rem; margin-left: 5px;">ADMIN</span>' : ''}
                </div>
                <div class="user-dropdown">
                    <a href="#" onclick="openPurchasesModal()"><i class="fas fa-shopping-bag"></i> Minhas Compras</a>
                    ${currentUser.isAdmin ? '<a href="admin-dashboard.html" target="_blank"><i class="fas fa-user-secret"></i> Painel Admin</a>' : ''}
                    <a href="#" onclick="logoutUser()"><i class="fas fa-sign-out-alt"></i> Sair</a>
                </div>
            `;
            userMenu.style.display = 'flex';
        }
    } else {
        if (loginBtn) loginBtn.style.display = 'block';
        if (registerBtn) registerBtn.style.display = 'block';
        if (logoutBtn) logoutBtn.style.display = 'none';
        if (userMenu) userMenu.style.display = 'none';
    }
    renderProducts();
}

function openPurchasesModal() {
    if (!currentUser) {
        showError('Você precisa estar logado para ver suas compras');
        return;
    }
    if (userPurchases.length === 0) {
        showMessage('Você ainda não fez nenhuma compra', 'info');
        return;
    }
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'purchasesModal';
    modal.innerHTML = `
        <div class="modal-content modal-lg">
            <div class="modal-header">
                <h2><i class="fas fa-shopping-bag"></i> Minhas Compras</h2>
                <button class="close-modal">&times;</button>
            </div>
            <div class="modal-body">
                <div class="purchases-tabs">
                    <button class="purchase-tab active" data-tab="all">Todas as Compras</button>
                    <button class="purchase-tab" data-tab="completed">Concluídas</button>
                    <button class="purchase-tab" data-tab="cancelled">Canceladas</button>
                </div>
                <div class="purchases-content">
                    <div class="purchases-grid" id="purchasesGrid">
                    </div>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            modalContent.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
        }
    }, 10);
    modal.querySelector('.close-modal').addEventListener('click', () => closeModal('purchasesModal'));
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal('purchasesModal');
    });
    modal.querySelectorAll('.purchase-tab').forEach(tab => {
        tab.addEventListener('click', function() {
            modal.querySelectorAll('.purchase-tab').forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            const tab = this.dataset.tab;
            renderPurchases(tab);
        });
    });
    renderPurchases('all');
}

function renderPurchases(filter = 'all') {
    const container = document.getElementById('purchasesGrid');
    if (!container) return;
    let filteredPurchases = userPurchases;
    if (filter !== 'all') {
        filteredPurchases = userPurchases.filter(purchase => purchase.status === filter);
    }
    if (filteredPurchases.length === 0) {
        container.innerHTML = `
            <div style="grid-column: 1 / -1; text-align: center; padding: 60px 20px;">
                <i class="fas fa-shopping-bag" style="font-size: 4rem; color: var(--dark-text); margin-bottom: 20px;"></i>
                <h3 style="color: var(--light-text); margin-bottom: 15px;">Nenhuma compra encontrada</h3>
                <p style="color: var(--medium-text);">Você não tem compras ${filter === 'all' ? '' : filter === 'completed' ? 'concluídas' : 'canceladas'}.</p>
            </div>
        `;
        return;
    }
    container.innerHTML = filteredPurchases.map(purchase => {
        const isCartCheckout = purchase.productId === 'cart-checkout';
        return `
            <div class="purchase-card">
                <div class="purchase-header">
                    <div>
                        <h4>${escapeHtml(purchase.productName)}</h4>
                        <div class="purchase-id">${purchase.id}</div>
                    </div>
                    <div class="purchase-status ${purchase.status}">
                        ${purchase.status === 'completed' ? 'CONCLUÍDO' : purchase.status === 'pending' ? 'PENDENTE' : 'CANCELADO'}
                    </div>
                </div>
                ${isCartCheckout ? `
                    <div class="purchase-items">
                        <h5>Itens da Compra:</h5>
                        ${purchase.items.map(item => `
                            <div style="display: flex; justify-content: space-between; margin: 5px 0; padding: 5px; background: rgba(255,255,255,0.05); border-radius: 5px;">
                                <span>${item.quantity}x ${item.name}</span>
                                <span>${(item.price * item.quantity).toFixed(4)} BTC</span>
                            </div>
                        `).join('')}
                    </div>
                ` : `
                    <div class="purchase-product">
                        <div class="purchase-product-image">
                            <i class="${getProductIcon(products.find(p => p.id === purchase.productId)?.category)}"></i>
                        </div>
                        <div class="purchase-product-info">
                            <h4>${escapeHtml(purchase.productName)}</h4>
                            <p>Chave: ${purchase.licenseKey}</p>
                        </div>
                    </div>
                `}
                <div class="purchase-meta">
                    <div>
                        <i class="fas fa-calendar"></i> ${formatDate(purchase.date)}
                    </div>
                    <div>
                        <i class="fas fa-box"></i> ${purchase.items?.length || 1} item(s)
                    </div>
                </div>
                <div class="purchase-total">
                    Total: ${purchase.total.toFixed(4)} ${purchase.currency}
                </div>
                <div class="purchase-actions">
                    ${purchase.status === 'completed' ? `
                        ${isCartCheckout ? `
                            <button class="btn btn-success" onclick="downloadCartPurchase('${purchase.id}')">
                                <i class="fas fa-download"></i> Baixar Tudo
                            </button>
                        ` : `
                            <button class="btn btn-success" onclick="downloadProduct('${purchase.productId}')">
                                <i class="fas fa-download"></i> Baixar
                            </button>
                        `}
                    ` : ''}
                    <button class="btn btn-info" onclick="viewPurchaseDetails('${purchase.id}')">
                        <i class="fas fa-info-circle"></i> Detalhes
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

function downloadCartPurchase(purchaseId) {
    const purchase = userPurchases.find(p => p.id === purchaseId);
    if (!purchase || !purchase.items) {
        showError('Compra não encontrada');
        return;
    }
    purchase.items.forEach(item => {
        setTimeout(() => {
            downloadProduct(item.productId);
        }, item.productId.charCodeAt(0) % 1000);
    });
    showMessage('Downloads iniciados! Verifique seus arquivos.', 'success');
}

function viewPurchaseDetails(purchaseId) {
    const purchase = userPurchases.find(p => p.id === purchaseId);
    if (!purchase) {
        showError('Compra não encontrada');
        return;
    }
    const isCartCheckout = purchase.productId === 'cart-checkout';
    let details = `DETALHES DA COMPRA\n\n`;
    details += `ID: ${purchase.id}\n`;
    details += `Produto: ${purchase.productName}\n`;
    details += `Status: ${purchase.status === 'completed' ? 'Concluído' : purchase.status === 'pending' ? 'Pendente' : 'Cancelado'}\n`;
    details += `Data: ${formatDate(purchase.date)}\n`;
    details += `Valor: ${purchase.total.toFixed(4)} ${purchase.currency}\n\n`;
    if (isCartCheckout) {
        details += `ITENS:\n`;
        purchase.items.forEach((item, index) => {
            details += `${index + 1}. ${item.quantity}x ${item.name}\n`;
            details += `   Preço: ${item.price.toFixed(4)} ${purchase.currency}\n`;
            details += `   Subtotal: ${(item.price * item.quantity).toFixed(4)} ${purchase.currency}\n`;
            details += `   Chave: ${item.licenseKey}\n\n`;
        });
    } else {
        details += `CHAVE DE LICENÇA:\n${purchase.licenseKey}\n\n`;
    }
    details += `RESUMO FINANCEIRO:\n`;
    details += `Subtotal: ${purchase.subtotal.toFixed(4)} ${purchase.currency}\n`;
    details += `Taxa (2%): ${purchase.fee.toFixed(4)} ${purchase.currency}\n`;
    details += `Total: ${purchase.total.toFixed(4)} ${purchase.currency}\n\n`;
    details += `Para suporte, entre em contato:\n`;
    details += `Email: support@luaworks.dev\n`;
    details += `Discord: discord.gg/luaworks`;
    alert(details);
}

function openLoginModal() {
    closeAllModals();
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'loginModal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-sign-in-alt"></i> Login</h2>
                <button class="close-modal">&times;</button>
            </div>
            <div class="modal-body">
                <form id="loginForm">
                    <div class="form-group">
                        <label for="loginEmail">Email</label>
                        <input type="email" id="loginEmail" required placeholder="seu@email.com">
                    </div>
                    <div class="form-group">
                        <label for="loginPassword">Senha</label>
                        <input type="password" id="loginPassword" required placeholder="Sua senha">
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">Entrar</button>
                </form>
                <p class="auth-switch">Não tem conta? <a href="#" onclick="openRegisterModal()">Registre-se</a></p>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            modalContent.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
        }
    }, 10);
    modal.querySelector('.close-modal').addEventListener('click', () => closeModal('loginModal'));
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal('loginModal');
    });
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        const result = await loginUser(email, password);
        if (result.success) {
            closeModal('loginModal');
        }
    });
}

function openRegisterModal() {
    closeAllModals();
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'registerModal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-user-plus"></i> Registro</h2>
                <button class="close-modal">&times;</button>
            </div>
            <div class="modal-body">
                <form id="registerForm">
                    <div class="form-group">
                        <label for="registerUsername">Nome de Usuário</label>
                        <input type="text" id="registerUsername" required minlength="3" maxlength="20" placeholder="Seu nome de usuário">
                    </div>
                    <div class="form-group">
                        <label for="registerEmail">Email</label>
                        <input type="email" id="registerEmail" required placeholder="seu@email.com">
                    </div>
                    <div class="form-group">
                        <label for="registerPassword">Senha</label>
                        <input type="password" id="registerPassword" required minlength="6" placeholder="Mínimo 6 caracteres">
                    </div>
                    <div class="form-group">
                        <label for="registerConfirm">Confirmar Senha</label>
                        <input type="password" id="registerConfirm" required minlength="6" placeholder="Confirme sua senha">
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">Criar Conta</button>
                </form>
                <p class="auth-switch">Já tem conta? <a href="#" onclick="openLoginModal()">Faça login</a></p>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            modalContent.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
        }
    }, 10);
    modal.querySelector('.close-modal').addEventListener('click', () => closeModal('registerModal'));
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal('registerModal');
    });
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('registerUsername').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('registerConfirm').value;
        if (password !== confirmPassword) {
            showError('As senhas não coincidem');
            return;
        }
        const result = await registerUser(username, email, password);
        if (result.success) {
            closeModal('registerModal');
        }
    });
}

function closeAllModals() {
    document.querySelectorAll('.modal').forEach(modal => {
        if (modal.id !== 'paymentModal' && modal.id !== 'cartModal' && modal.id !== 'downloadModal') {
            modal.remove();
        }
    });
    document.body.style.overflow = 'auto';
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    const modalContent = modal.querySelector('.modal-content');
    if (modalContent) {
        modalContent.style.opacity = '0';
        modalContent.style.transform = 'translateY(-50px)';
    }
    setTimeout(() => {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
        modal.remove();
    }, 300);
}

function getCategoryColor(category) {
    const colors = {
        'automation': '#00ff88',
        'bot': '#0099ff',
        'system': '#ff00ff',
        'utility': '#ffaa00',
        'tool': '#ff3366'
    };
    return colors[category] || '#00ff88';
}

function getCategoryIcon(category) {
    const icons = {
        'automation': 'fas fa-robot',
        'bot': 'fas fa-brain',
        'system': 'fas fa-bolt',
        'utility': 'fas fa-tools',
        'tool': 'fas fa-wrench'
    };
    return icons[category] || 'fas fa-code';
}

function getProductIcon(category) {
    const icons = {
        'automation': 'fas fa-robot',
        'bot': 'fas fa-brain',
        'system': 'fas fa-bolt',
        'utility': 'fas fa-tools',
        'tool': 'fas fa-wrench'
    };
    return icons[category] || 'fas fa-file-code';
}

function getCategoryName(category) {
    const names = {
        'automation': 'Automação',
        'bot': 'Bot',
        'system': 'Sistema',
        'utility': 'Utilitário',
        'tool': 'Ferramenta'
    };
    return names[category] || 'Automação';
}

function formatDate(dateString) {
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('pt-BR', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (e) {
        return 'Data não disponível';
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showMessage(message, type = 'info') {
    let container = document.getElementById('messageContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'messageContainer';
        document.body.appendChild(container);
    }
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    container.appendChild(messageDiv);
    setTimeout(() => {
        messageDiv.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (messageDiv.parentNode === container) {
                container.removeChild(messageDiv);
            }
        }, 300);
    }, 5000);
}

function showError(message) {
    showMessage(message, 'error');
}

function viewProductDetails(productId) {
    const product = products.find(p => p.id === productId) || 
                    upcomingProducts.find(p => p.id === productId);
    if (!product) {
        showError('Produto não encontrado');
        return;
    }
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'productDetailsModal';
    modal.innerHTML = `
        <div class="modal-content modal-lg">
            <div class="modal-header">
                <h2>${escapeHtml(product.name)}</h2>
                <button class="close-modal">&times;</button>
            </div>
            <div class="modal-body">
                <div class="product-details">
                    <div class="product-details-header">
                        <div class="product-image-large">
                            <i class="${getProductIcon(product.category)}"></i>
                        </div>
                        <div class="product-info">
                            <h3>${escapeHtml(product.name)}</h3>
                            <p class="product-description">${escapeHtml(product.description)}</p>
                            <div class="product-meta-details">
                                <span class="product-category ${product.category}">
                                    <i class="${getCategoryIcon(product.category)}"></i> ${getCategoryName(product.category)}
                                </span>
                                <div class="product-rating">
                                    ${renderStars(product.rating || 0)}
                                    <span class="rating-text">${product.rating || 'N/A'} (${product.downloads || 0} downloads)</span>
                                </div>
                            </div>
                            <div class="product-price-details">
                                <div class="price-main">${product.price} ${product.currency}</div>
                                ${product.originalPrice ? `<div class="price-original">${product.originalPrice} ${product.currency}</div>` : ''}
                            </div>
                        </div>
                    </div>
                    <div class="product-details-content">
                        <div class="details-section">
                            <h4><i class="fas fa-star"></i> Recursos Principais</h4>
                            <ul class="features-list">
                                ${(product.features || []).map(feature => `
                                    <li><i class="fas fa-check"></i> ${escapeHtml(feature)}</li>
                                `).join('')}
                            </ul>
                        </div>
                        <div class="details-section">
                            <h4><i class="fas fa-info-circle"></i> Informações Técnicas</h4>
                            <div class="technical-info">
                                <div class="info-row">
                                    <span class="info-label">Versão:</span>
                                    <span class="info-value">${product.version || '1.0.0'}</span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Tamanho:</span>
                                    <span class="info-value">${product.fileSize || 'N/A'}</span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Atualizado em:</span>
                                    <span class="info-value">${formatDate(product.lastUpdate || product.uploadDate)}</span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Desenvolvedor:</span>
                                    <span class="info-value">${product.developer || 'Lua Works Team'}</span>
                                </div>
                            </div>
                        </div>
                        <div class="details-section">
                            <h4><i class="fas fa-shopping-cart"></i> Comprar</h4>
                            <div class="purchase-actions">
                                ${product.status === 'upcoming' ? `
                                    <button class="btn btn-secondary" disabled>
                                        <i class="fas fa-clock"></i> Em Breve
                                    </button>
                                    <p class="upcoming-info">Lançamento previsto: ${product.expectedRelease ? formatDate(product.expectedRelease) : 'Em breve'}</p>
                                ` : userPurchases.some(p => p.productId === product.id) ? `
                                    <button class="btn btn-success" onclick="downloadProduct('${product.id}'); closeModal('productDetailsModal')">
                                        <i class="fas fa-download"></i> Baixar Agora
                                    </button>
                                    <p class="purchased-info">Você já possui este produto</p>
                                ` : `
                                    </button>
                                    <button class="btn btn-primary" onclick="openPaymentModal('${product.id}'); closeModal('productDetailsModal')">
                                        <i class="fas fa-shopping-cart"></i> Comprar Agora
                                    </button>
                                    <p class="price-info">Apenas ${product.price} ${product.currency}</p>
                                `}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            modalContent.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
        }
    }, 10);
    modal.querySelector('.close-modal').addEventListener('click', () => closeModal('productDetailsModal'));
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal('productDetailsModal');
    });
}

function setupAdminSystem() {
    document.addEventListener('keydown', (e) => {
        adminSequence.push(e.code);
        if (adminSequence.length > adminPassword.length) {
            adminSequence.shift();
        }
        if (JSON.stringify(adminSequence) === JSON.stringify(adminPassword)) {
            activateAdminMode();
        }
    });
    const logo = document.querySelector('.logo');
    if (logo) {
        let clickCount = 0;
        let clickTimer;
        logo.addEventListener('click', () => {
            clickCount++;
            if (clickTimer) {
                clearTimeout(clickTimer);
            }
            clickTimer = setTimeout(() => {
                if (clickCount >= 3) {
                    showAdminAccessPanel();
                }
                clickCount = 0;
            }, 500);
        });
    }
}

function activateAdminMode() {
    if (!currentUser?.isAdmin) {
        showMessage('Admin: Usuário não tem permissões', 'error');
        return;
    }
    adminEnabled = true;
    const indicator = document.createElement('div');
    indicator.id = 'adminIndicator';
    indicator.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: linear-gradient(45deg, #ff3366, #ff00ff);
        color: white;
        padding: 5px 10px;
        border-radius: 5px;
        font-size: 12px;
        font-weight: bold;
        z-index: 9999;
        display: flex;
        align-items: center;
        gap: 5px;
        opacity: 0.8;
    `;
    indicator.innerHTML = '<i class="fas fa-user-secret"></i> ADMIN MODE';
    document.body.appendChild(indicator);
    addAdminFloatingButton();
    showMessage('Modo Administrador ativado! Acesso completo liberado.', 'success');
    console.log('Modo admin ativado');
}

function addAdminFloatingButton() {
    const floatingBtn = document.createElement('button');
    floatingBtn.id = 'adminFloatingBtn';
    floatingBtn.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background: linear-gradient(45deg, #ff3366, #ff00ff);
        color: white;
        border: none;
        cursor: pointer;
        font-size: 24px;
        z-index: 9998;
        box-shadow: 0 5px 15px rgba(255, 51, 102, 0.3);
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.3s ease;
    `;
    floatingBtn.innerHTML = '<i class="fas fa-cogs"></i>';
    floatingBtn.addEventListener('mouseenter', () => {
        floatingBtn.style.transform = 'scale(1.1)';
        floatingBtn.style.boxShadow = '0 8px 25px rgba(255, 51, 102, 0.5)';
    });
    floatingBtn.addEventListener('mouseleave', () => {
        floatingBtn.style.transform = 'scale(1)';
        floatingBtn.style.boxShadow = '0 5px 15px rgba(255, 51, 102, 0.3)';
    });
    floatingBtn.addEventListener('click', function() {
        window.open('admin-dashboard.html', '_blank');
    });
    document.body.appendChild(floatingBtn);
}

function showAdminAccessPanel() {
    if (!currentUser) {
        showMessage('Faça login primeiro', 'warning');
        return;
    }
    if (!currentUser.isAdmin) {
        showMessage('Acesso negado: Permissões insuficientes', 'error');
        return;
    }
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'adminAccessModal';
    modal.style.cssText = `
        background: rgba(0, 0, 0, 0.95);
        align-items: center;
        justify-content: center;
    `;
    modal.innerHTML = `
        <div class="modal-content" style="max-width: 500px; background: linear-gradient(135deg, #1a1a2e, #0f0f23);">
            <div class="modal-header" style="border-bottom: 1px solid rgba(255, 51, 102, 0.3);">
                <h2><i class="fas fa-user-secret"></i> Acesso Administrativo</h2>
                <button class="close-modal">&times;</button>
            </div>
            <div class="modal-body">
                <div style="text-align: center; padding: 20px 0;">
                    <div style="font-size: 4rem; color: #ff3366; margin-bottom: 20px;">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <h3 style="color: #ffffff; margin-bottom: 10px;">Olá, ${currentUser.username}!</h3>
                    <p style="color: #aaccff; margin-bottom: 30px;">Nível de acesso: Administrador</p>
                </div>
                <div style="display: grid; gap: 15px; margin-bottom: 30px;">
                    <a href="admin-dashboard.html" target="_blank" class="btn btn-primary" style="justify-content: center; text-decoration: none;">
                        <i class="fas fa-tachometer-alt"></i> Dashboard Admin
                    </a>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    setTimeout(() => {
        const modalContent = modal.querySelector('.modal-content');
        if (modalContent) {
            modalContent.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
        }
    }, 10);
    modal.querySelector('.close-modal').addEventListener('click', () => closeModal('adminAccessModal'));
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal('adminAccessModal');
    });
}

function showAdminDashboard() {
    window.open('admin-dashboard.html', '_blank');
}

setTimeout(() => {
    if (!currentUser) {
        const existingAdmin = localStorage.getItem('lua_works_admin_created');
        if (!existingAdmin) {
            const adminUser = {
                id: 'admin_001',
                username: 'admin',
                email: 'admin@luaworks.dev',
                profile: {
                    avatar: 'https://ui-avatars.com/api/?name=Admin&background=ff3366&color=ffffff'
                },
                isAdmin: true,
                joinDate: new Date().toISOString()
            };
            const adminToken = 'admin_token_' + Math.random().toString(36).substr(2);
            localStorage.setItem('auth_token', adminToken);
            localStorage.setItem('user_data', JSON.stringify(adminUser));
            localStorage.setItem('user_purchases', '[]');
            localStorage.setItem('lua_works_admin_created', 'true');
            console.log('Usuário admin criado automaticamente');
            console.log('Login: admin@luaworks.dev');
            console.log('Senha: qualquer uma (sistema de demonstração)');
        }
    }
}, 2000);

if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    try {
        const socket = new WebSocket('ws://localhost:3001');
        socket.onmessage = (event) => {
            if (event.data === 'reload') {
                console.log('Recebido comando de recarregar...');
                location.reload();
            }
        };
        socket.onerror = () => {
        };
    } catch (e) {
    }
}

window.openPaymentModal = openPaymentModal;
window.selectCurrency = selectCurrency;
window.copyWalletAddress = copyWalletAddress;
window.confirmPayment = confirmPayment;
window.filterProducts = filterProducts;
window.toggleMobileMenu = toggleMobileMenu;
window.downloadProduct = downloadProduct;
window.viewProductDetails = viewProductDetails;
window.loginUser = loginUser;
window.logoutUser = logoutUser;
window.openLoginModal = openLoginModal;
window.openRegisterModal = openRegisterModal;
window.closeModal = closeModal;
window.closeDownloadModal = closeDownloadModal;
window.copyToClipboard = copyToClipboard;
window.downloadAllFiles = downloadAllFiles;
window.downloadFile = downloadFile;
window.downloadCartPurchase = downloadCartPurchase;
window.viewPurchaseDetails = viewPurchaseDetails;
window.addToCart = addToCart;
window.removeFromCart = removeFromCart;
window.openPurchasesModal = openPurchasesModal;
window.showAdminAccessPanel = showAdminAccessPanel;
window.showAdminDashboard = showAdminDashboard;
