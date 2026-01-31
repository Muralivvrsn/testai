'use client';

import React, { useState, useEffect, useReducer, useCallback, createContext, useContext } from 'react';

// ============== Types ==============
interface Product {
  id: string;
  name: string;
  category: string;
  price: number;
  originalPrice?: number;
  rating: number;
  reviewCount: number;
  description: string;
  images: string[];
  variants: {
    colors: string[];
    sizes: string[];
  };
  stock: number;
  badge?: string;
  emoji: string;
}

interface CartItem {
  product: Product;
  quantity: number;
  selectedColor: string;
  selectedSize: string;
}

interface User {
  id: string;
  name: string;
  email: string;
  avatar: string;
}

interface Toast {
  id: string;
  type: 'success' | 'error' | 'info';
  message: string;
}

interface ShippingInfo {
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  state: string;
  zip: string;
  country: string;
}

interface PaymentInfo {
  method: 'card' | 'paypal' | 'applepay';
  cardNumber: string;
  expiry: string;
  cvv: string;
  nameOnCard: string;
}

// ============== Context ==============
interface AppState {
  user: User | null;
  cart: CartItem[];
  wishlist: string[];
  toasts: Toast[];
  isCartOpen: boolean;
  isAuthModalOpen: boolean;
  checkoutStep: number;
  shippingInfo: ShippingInfo;
  paymentInfo: PaymentInfo;
  orderComplete: boolean;
  orderId: string | null;
  loading: boolean;
}

type Action =
  | { type: 'SET_USER'; payload: User | null }
  | { type: 'ADD_TO_CART'; payload: CartItem }
  | { type: 'REMOVE_FROM_CART'; payload: string }
  | { type: 'UPDATE_QUANTITY'; payload: { productId: string; quantity: number } }
  | { type: 'CLEAR_CART' }
  | { type: 'TOGGLE_WISHLIST'; payload: string }
  | { type: 'ADD_TOAST'; payload: Toast }
  | { type: 'REMOVE_TOAST'; payload: string }
  | { type: 'SET_CART_OPEN'; payload: boolean }
  | { type: 'SET_AUTH_MODAL_OPEN'; payload: boolean }
  | { type: 'SET_CHECKOUT_STEP'; payload: number }
  | { type: 'SET_SHIPPING_INFO'; payload: Partial<ShippingInfo> }
  | { type: 'SET_PAYMENT_INFO'; payload: Partial<PaymentInfo> }
  | { type: 'COMPLETE_ORDER'; payload: string }
  | { type: 'RESET_CHECKOUT' }
  | { type: 'SET_LOADING'; payload: boolean };

const initialState: AppState = {
  user: null,
  cart: [],
  wishlist: [],
  toasts: [],
  isCartOpen: false,
  isAuthModalOpen: false,
  checkoutStep: 0,
  shippingInfo: {
    firstName: '', lastName: '', email: '', phone: '',
    address: '', city: '', state: '', zip: '', country: 'US'
  },
  paymentInfo: {
    method: 'card', cardNumber: '', expiry: '', cvv: '', nameOnCard: ''
  },
  orderComplete: false,
  orderId: null,
  loading: false,
};

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'SET_USER':
      return { ...state, user: action.payload };
    case 'ADD_TO_CART':
      const existing = state.cart.find(
        item => item.product.id === action.payload.product.id &&
          item.selectedColor === action.payload.selectedColor &&
          item.selectedSize === action.payload.selectedSize
      );
      if (existing) {
        return {
          ...state,
          cart: state.cart.map(item =>
            item === existing
              ? { ...item, quantity: item.quantity + action.payload.quantity }
              : item
          )
        };
      }
      return { ...state, cart: [...state.cart, action.payload] };
    case 'REMOVE_FROM_CART':
      return { ...state, cart: state.cart.filter(item => item.product.id !== action.payload) };
    case 'UPDATE_QUANTITY':
      return {
        ...state,
        cart: state.cart.map(item =>
          item.product.id === action.payload.productId
            ? { ...item, quantity: action.payload.quantity }
            : item
        ).filter(item => item.quantity > 0)
      };
    case 'CLEAR_CART':
      return { ...state, cart: [] };
    case 'TOGGLE_WISHLIST':
      return {
        ...state,
        wishlist: state.wishlist.includes(action.payload)
          ? state.wishlist.filter(id => id !== action.payload)
          : [...state.wishlist, action.payload]
      };
    case 'ADD_TOAST':
      return { ...state, toasts: [...state.toasts, action.payload] };
    case 'REMOVE_TOAST':
      return { ...state, toasts: state.toasts.filter(t => t.id !== action.payload) };
    case 'SET_CART_OPEN':
      return { ...state, isCartOpen: action.payload };
    case 'SET_AUTH_MODAL_OPEN':
      return { ...state, isAuthModalOpen: action.payload };
    case 'SET_CHECKOUT_STEP':
      return { ...state, checkoutStep: action.payload };
    case 'SET_SHIPPING_INFO':
      return { ...state, shippingInfo: { ...state.shippingInfo, ...action.payload } };
    case 'SET_PAYMENT_INFO':
      return { ...state, paymentInfo: { ...state.paymentInfo, ...action.payload } };
    case 'COMPLETE_ORDER':
      return { ...state, orderComplete: true, orderId: action.payload, cart: [] };
    case 'RESET_CHECKOUT':
      return { ...state, checkoutStep: 0, orderComplete: false, orderId: null };
    case 'SET_LOADING':
      return { ...state, loading: action.payload };
    default:
      return state;
  }
}

const AppContext = createContext<{
  state: AppState;
  dispatch: React.Dispatch<Action>;
  addToast: (type: Toast['type'], message: string) => void;
} | null>(null);

function useApp() {
  const context = useContext(AppContext);
  if (!context) throw new Error('useApp must be used within AppProvider');
  return context;
}

// ============== Sample Data ==============
const products: Product[] = [
  {
    id: '1', name: 'Premium Wireless Headphones', category: 'Electronics',
    price: 299.99, originalPrice: 399.99, rating: 4.8, reviewCount: 1247,
    description: 'Experience premium sound quality with active noise cancellation and 30-hour battery life.',
    images: ['main', 'side', 'back'], variants: { colors: ['Black', 'White', 'Blue'], sizes: [] },
    stock: 15, badge: 'SALE', emoji: '🎧'
  },
  {
    id: '2', name: 'Smart Fitness Watch Pro', category: 'Electronics',
    price: 249.99, rating: 4.6, reviewCount: 892,
    description: 'Track your health metrics, GPS, heart rate monitor, and 7-day battery life.',
    images: ['main', 'side'], variants: { colors: ['Black', 'Silver', 'Rose Gold'], sizes: ['S', 'M', 'L'] },
    stock: 8, badge: 'NEW', emoji: '⌚'
  },
  {
    id: '3', name: 'Ergonomic Office Chair', category: 'Furniture',
    price: 549.99, originalPrice: 699.99, rating: 4.9, reviewCount: 567,
    description: 'Adjustable lumbar support, breathable mesh back, and premium build quality.',
    images: ['main', 'side', 'detail'], variants: { colors: ['Black', 'Gray'], sizes: [] },
    stock: 3, emoji: '🪑'
  },
  {
    id: '4', name: 'Minimalist Backpack', category: 'Accessories',
    price: 89.99, rating: 4.5, reviewCount: 2341,
    description: 'Water-resistant material, laptop compartment, and multiple pockets.',
    images: ['main', 'back'], variants: { colors: ['Black', 'Navy', 'Gray', 'Green'], sizes: [] },
    stock: 50, emoji: '🎒'
  },
  {
    id: '5', name: 'Mechanical Keyboard RGB', category: 'Electronics',
    price: 159.99, rating: 4.7, reviewCount: 1893,
    description: 'Cherry MX switches, full RGB backlighting, and aluminum frame.',
    images: ['main', 'side'], variants: { colors: ['Black', 'White'], sizes: [] },
    stock: 25, badge: 'BESTSELLER', emoji: '⌨️'
  },
  {
    id: '6', name: 'Ultra-Slim Laptop Stand', category: 'Accessories',
    price: 79.99, originalPrice: 99.99, rating: 4.4, reviewCount: 678,
    description: 'Aluminum construction, foldable design, and universal compatibility.',
    images: ['main'], variants: { colors: ['Silver', 'Space Gray'], sizes: [] },
    stock: 42, emoji: '💻'
  },
  {
    id: '7', name: 'Noise Cancelling Earbuds', category: 'Electronics',
    price: 179.99, rating: 4.6, reviewCount: 3421,
    description: 'Compact design, 8-hour battery, and wireless charging case.',
    images: ['main', 'case'], variants: { colors: ['White', 'Black'], sizes: [] },
    stock: 0, emoji: '🎵'
  },
  {
    id: '8', name: 'Designer Desk Lamp', category: 'Furniture',
    price: 129.99, rating: 4.3, reviewCount: 456,
    description: 'Adjustable brightness, color temperature control, and USB charging port.',
    images: ['main'], variants: { colors: ['White', 'Black', 'Wood'], sizes: [] },
    stock: 18, emoji: '💡'
  },
];

const categories = ['All', 'Electronics', 'Furniture', 'Accessories'];

// ============== Components ==============

function Header() {
  const { state, dispatch } = useApp();
  const [searchQuery, setSearchQuery] = useState('');
  const [showSearchResults, setShowSearchResults] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);

  const searchResults = products.filter(p =>
    p.name.toLowerCase().includes(searchQuery.toLowerCase())
  ).slice(0, 5);

  const cartCount = state.cart.reduce((sum, item) => sum + item.quantity, 0);

  return (
    <header className="header" data-testid="header">
      <a href="/" className="logo" data-testid="logo">ShopFlow</a>

      <nav className="nav-links" data-testid="nav-links">
        <a href="#" className="nav-link" data-testid="nav-products">Products</a>
        <a href="#" className="nav-link" data-testid="nav-deals">Deals</a>
        <a href="#" className="nav-link" data-testid="nav-categories">Categories</a>
        <a href="#" className="nav-link" data-testid="nav-support">Support</a>
      </nav>

      <div className="search-container" data-testid="search-container">
        <span className="search-icon">🔍</span>
        <input
          type="text"
          className="search-input"
          placeholder="Search products..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onFocus={() => setShowSearchResults(true)}
          onBlur={() => setTimeout(() => setShowSearchResults(false), 200)}
          data-testid="search-input"
        />
        {showSearchResults && searchQuery && (
          <div className="search-results" data-testid="search-results">
            {searchResults.map(product => (
              <div
                key={product.id}
                className="search-result-item"
                data-testid={`search-result-${product.id}`}
                onClick={() => {
                  setSearchQuery('');
                  setShowSearchResults(false);
                }}
              >
                <div className="search-result-image">{product.emoji}</div>
                <div>
                  <div style={{ fontWeight: 500 }}>{product.name}</div>
                  <div style={{ fontSize: '0.875rem', color: '#64748b' }}>${product.price}</div>
                </div>
              </div>
            ))}
            {searchResults.length === 0 && (
              <div style={{ padding: '1rem', textAlign: 'center', color: '#64748b' }}>
                No products found
              </div>
            )}
          </div>
        )}
      </div>

      <div className="header-actions" data-testid="header-actions">
        <button
          className="cart-button"
          onClick={() => dispatch({ type: 'SET_CART_OPEN', payload: true })}
          data-testid="cart-button"
        >
          🛒
          {cartCount > 0 && <span className="cart-badge" data-testid="cart-badge">{cartCount}</span>}
        </button>

        {state.user ? (
          <div className="user-menu" data-testid="user-menu">
            <button
              className="user-btn"
              onClick={() => setShowUserMenu(!showUserMenu)}
              data-testid="user-button"
            >
              <div className="user-avatar">{state.user.name[0]}</div>
              <span>{state.user.name.split(' ')[0]}</span>
            </button>
            <div className={`user-dropdown ${showUserMenu ? 'open' : ''}`} data-testid="user-dropdown">
              <button className="dropdown-item" data-testid="dropdown-profile">
                👤 My Profile
              </button>
              <button className="dropdown-item" data-testid="dropdown-orders">
                📦 Orders
              </button>
              <button className="dropdown-item" data-testid="dropdown-wishlist">
                ❤️ Wishlist ({state.wishlist.length})
              </button>
              <button className="dropdown-item" data-testid="dropdown-settings">
                ⚙️ Settings
              </button>
              <div className="dropdown-divider" />
              <button
                className="dropdown-item"
                onClick={() => {
                  dispatch({ type: 'SET_USER', payload: null });
                  setShowUserMenu(false);
                }}
                data-testid="dropdown-logout"
              >
                🚪 Logout
              </button>
            </div>
          </div>
        ) : (
          <button
            className="nav-link"
            onClick={() => dispatch({ type: 'SET_AUTH_MODAL_OPEN', payload: true })}
            data-testid="login-button"
            style={{ background: 'none', border: 'none', cursor: 'pointer' }}
          >
            Sign In
          </button>
        )}
      </div>
    </header>
  );
}

function ProductFilters({
  selectedCategory,
  setSelectedCategory,
  priceRange,
  setPriceRange,
  sortBy,
  setSortBy,
  inStockOnly,
  setInStockOnly
}: {
  selectedCategory: string;
  setSelectedCategory: (c: string) => void;
  priceRange: [number, number];
  setPriceRange: (r: [number, number]) => void;
  sortBy: string;
  setSortBy: (s: string) => void;
  inStockOnly: boolean;
  setInStockOnly: (b: boolean) => void;
}) {
  return (
    <aside className="filters-sidebar" data-testid="filters-sidebar">
      <div className="filter-card" data-testid="category-filter">
        <h3 className="filter-title">Category</h3>
        <div className="filter-options">
          {categories.map(cat => (
            <label key={cat} className="filter-option">
              <input
                type="radio"
                name="category"
                checked={selectedCategory === cat}
                onChange={() => setSelectedCategory(cat)}
                data-testid={`category-${cat.toLowerCase()}`}
              />
              {cat}
            </label>
          ))}
        </div>
      </div>

      <div className="filter-card" data-testid="price-filter">
        <h3 className="filter-title">Price Range</h3>
        <div className="price-range">
          <input
            type="number"
            className="price-input"
            placeholder="Min"
            value={priceRange[0] || ''}
            onChange={(e) => setPriceRange([Number(e.target.value), priceRange[1]])}
            data-testid="price-min"
          />
          <span>-</span>
          <input
            type="number"
            className="price-input"
            placeholder="Max"
            value={priceRange[1] || ''}
            onChange={(e) => setPriceRange([priceRange[0], Number(e.target.value)])}
            data-testid="price-max"
          />
        </div>
        <input
          type="range"
          className="price-slider"
          min="0"
          max="700"
          value={priceRange[1]}
          onChange={(e) => setPriceRange([priceRange[0], Number(e.target.value)])}
          data-testid="price-slider"
        />
      </div>

      <div className="filter-card" data-testid="sort-filter">
        <h3 className="filter-title">Sort By</h3>
        <select
          className="form-select"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value)}
          data-testid="sort-select"
        >
          <option value="featured">Featured</option>
          <option value="price-low">Price: Low to High</option>
          <option value="price-high">Price: High to Low</option>
          <option value="rating">Highest Rated</option>
          <option value="newest">Newest</option>
        </select>
      </div>

      <div className="filter-card" data-testid="availability-filter">
        <h3 className="filter-title">Availability</h3>
        <label className="filter-option">
          <input
            type="checkbox"
            checked={inStockOnly}
            onChange={(e) => setInStockOnly(e.target.checked)}
            data-testid="in-stock-checkbox"
          />
          In Stock Only
        </label>
      </div>

      <button
        className="add-to-cart-btn"
        onClick={() => {
          setSelectedCategory('All');
          setPriceRange([0, 700]);
          setSortBy('featured');
          setInStockOnly(false);
        }}
        data-testid="clear-filters"
        style={{ background: '#64748b' }}
      >
        Clear All Filters
      </button>
    </aside>
  );
}

function ProductCard({ product, onViewDetails }: { product: Product; onViewDetails: (p: Product) => void }) {
  const { state, dispatch, addToast } = useApp();
  const isWishlisted = state.wishlist.includes(product.id);

  const handleAddToCart = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (product.stock === 0) return;

    dispatch({
      type: 'ADD_TO_CART',
      payload: {
        product,
        quantity: 1,
        selectedColor: product.variants.colors[0] || '',
        selectedSize: product.variants.sizes[0] || ''
      }
    });
    addToast('success', `${product.name} added to cart!`);
  };

  return (
    <div
      className="product-card"
      onClick={() => onViewDetails(product)}
      data-testid={`product-card-${product.id}`}
    >
      <div className="product-image">
        <span style={{ fontSize: '4rem' }}>{product.emoji}</span>
        {product.badge && <span className="product-badge">{product.badge}</span>}
        <button
          className={`product-wishlist ${isWishlisted ? 'active' : ''}`}
          onClick={(e) => {
            e.stopPropagation();
            dispatch({ type: 'TOGGLE_WISHLIST', payload: product.id });
          }}
          data-testid={`wishlist-${product.id}`}
        >
          {isWishlisted ? '❤️' : '🤍'}
        </button>
      </div>
      <div className="product-info">
        <div className="product-category">{product.category}</div>
        <h3 className="product-name">{product.name}</h3>
        <div className="product-rating">
          {'⭐'.repeat(Math.floor(product.rating))}
          <span style={{ color: '#64748b', marginLeft: '0.5rem' }}>
            {product.rating} ({product.reviewCount})
          </span>
        </div>
        <div className="product-price">
          <span className="current-price">${product.price}</span>
          {product.originalPrice && (
            <span className="original-price">${product.originalPrice}</span>
          )}
        </div>
        <button
          className="add-to-cart-btn"
          onClick={handleAddToCart}
          disabled={product.stock === 0}
          data-testid={`add-to-cart-${product.id}`}
        >
          {product.stock === 0 ? 'Out of Stock' : 'Add to Cart'}
        </button>
      </div>
    </div>
  );
}

function ProductDetail({ product, onClose }: { product: Product; onClose: () => void }) {
  const { dispatch, addToast } = useApp();
  const [selectedColor, setSelectedColor] = useState(product.variants.colors[0] || '');
  const [selectedSize, setSelectedSize] = useState(product.variants.sizes[0] || '');
  const [quantity, setQuantity] = useState(1);
  const [selectedImage, setSelectedImage] = useState(0);

  const handleAddToCart = () => {
    dispatch({
      type: 'ADD_TO_CART',
      payload: { product, quantity, selectedColor, selectedSize }
    });
    addToast('success', `${quantity}x ${product.name} added to cart!`);
  };

  const handleBuyNow = () => {
    dispatch({
      type: 'ADD_TO_CART',
      payload: { product, quantity, selectedColor, selectedSize }
    });
    dispatch({ type: 'SET_CART_OPEN', payload: true });
  };

  return (
    <div className="modal-overlay open" onClick={onClose} data-testid="product-detail-modal">
      <div
        className="product-detail"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '900px', margin: '2rem auto' }}
      >
        <div className="product-gallery">
          <div className="main-image" data-testid="product-main-image">
            <span style={{ fontSize: '8rem' }}>{product.emoji}</span>
          </div>
          <div className="thumbnail-list">
            {product.images.map((img, idx) => (
              <div
                key={idx}
                className={`thumbnail ${selectedImage === idx ? 'active' : ''}`}
                onClick={() => setSelectedImage(idx)}
                data-testid={`thumbnail-${idx}`}
              >
                {product.emoji}
              </div>
            ))}
          </div>
        </div>

        <div className="product-detail-info">
          <button
            onClick={onClose}
            style={{ float: 'right', background: 'none', border: 'none', fontSize: '1.5rem', cursor: 'pointer' }}
            data-testid="close-detail"
          >
            ✕
          </button>
          <div className="product-category">{product.category}</div>
          <h1>{product.name}</h1>
          <div className="product-rating" style={{ fontSize: '1rem' }}>
            {'⭐'.repeat(Math.floor(product.rating))}
            <span style={{ color: '#64748b', marginLeft: '0.5rem' }}>
              {product.rating} ({product.reviewCount} reviews)
            </span>
          </div>
          <div className="detail-price">
            ${product.price}
            {product.originalPrice && (
              <span style={{ fontSize: '1rem', color: '#64748b', textDecoration: 'line-through', marginLeft: '0.5rem' }}>
                ${product.originalPrice}
              </span>
            )}
          </div>
          <p className="detail-description">{product.description}</p>

          {product.variants.colors.length > 0 && (
            <div className="variant-selector" data-testid="color-selector">
              <div className="variant-label">Color: {selectedColor}</div>
              <div className="variant-options">
                {product.variants.colors.map(color => (
                  <div
                    key={color}
                    className={`variant-option ${selectedColor === color ? 'selected' : ''}`}
                    onClick={() => setSelectedColor(color)}
                    data-testid={`color-${color.toLowerCase()}`}
                  >
                    {color}
                  </div>
                ))}
              </div>
            </div>
          )}

          {product.variants.sizes.length > 0 && (
            <div className="variant-selector" data-testid="size-selector">
              <div className="variant-label">Size: {selectedSize}</div>
              <div className="variant-options">
                {product.variants.sizes.map(size => (
                  <div
                    key={size}
                    className={`variant-option ${selectedSize === size ? 'selected' : ''}`}
                    onClick={() => setSelectedSize(size)}
                    data-testid={`size-${size.toLowerCase()}`}
                  >
                    {size}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="quantity-selector" data-testid="quantity-selector">
            <span className="variant-label">Quantity:</span>
            <div className="quantity-controls">
              <button
                className="quantity-btn"
                onClick={() => setQuantity(Math.max(1, quantity - 1))}
                data-testid="quantity-decrease"
              >
                −
              </button>
              <span className="quantity-value" data-testid="quantity-value">{quantity}</span>
              <button
                className="quantity-btn"
                onClick={() => setQuantity(Math.min(product.stock, quantity + 1))}
                data-testid="quantity-increase"
              >
                +
              </button>
            </div>
            <span className={`stock-status ${product.stock === 0 ? 'out-of-stock' : product.stock < 5 ? 'low-stock' : 'in-stock'}`}>
              {product.stock === 0 ? 'Out of Stock' : product.stock < 5 ? `Only ${product.stock} left!` : 'In Stock'}
            </span>
          </div>

          <div className="detail-actions">
            <button
              className="buy-now-btn"
              onClick={handleBuyNow}
              disabled={product.stock === 0}
              data-testid="buy-now-btn"
            >
              Buy Now
            </button>
            <button
              className="add-cart-btn"
              onClick={handleAddToCart}
              disabled={product.stock === 0}
              data-testid="add-to-cart-detail"
            >
              Add to Cart
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function CartSidebar() {
  const { state, dispatch } = useApp();
  const subtotal = state.cart.reduce((sum, item) => sum + item.product.price * item.quantity, 0);
  const shipping = subtotal > 100 ? 0 : 9.99;
  const total = subtotal + shipping;

  const handleCheckout = () => {
    dispatch({ type: 'SET_CART_OPEN', payload: false });
    dispatch({ type: 'SET_CHECKOUT_STEP', payload: 1 });
  };

  return (
    <>
      <div
        className={`cart-overlay ${state.isCartOpen ? 'open' : ''}`}
        onClick={() => dispatch({ type: 'SET_CART_OPEN', payload: false })}
        data-testid="cart-overlay"
      />
      <div className={`cart-sidebar ${state.isCartOpen ? 'open' : ''}`} data-testid="cart-sidebar">
        <div className="cart-header">
          <h2>Shopping Cart ({state.cart.length})</h2>
          <button
            className="cart-close"
            onClick={() => dispatch({ type: 'SET_CART_OPEN', payload: false })}
            data-testid="cart-close"
          >
            ✕
          </button>
        </div>

        <div className="cart-items">
          {state.cart.length === 0 ? (
            <div className="cart-empty" data-testid="cart-empty">
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🛒</div>
              <p>Your cart is empty</p>
              <p style={{ fontSize: '0.875rem' }}>Add some products to get started!</p>
            </div>
          ) : (
            state.cart.map((item, idx) => (
              <div key={idx} className="cart-item" data-testid={`cart-item-${item.product.id}`}>
                <div className="cart-item-image">{item.product.emoji}</div>
                <div className="cart-item-info">
                  <div className="cart-item-name">{item.product.name}</div>
                  <div className="cart-item-variant">
                    {item.selectedColor && `${item.selectedColor}`}
                    {item.selectedSize && ` / ${item.selectedSize}`}
                  </div>
                  <div className="cart-item-price">${item.product.price}</div>
                  <div className="cart-item-quantity">
                    <button
                      className="cart-qty-btn"
                      onClick={() => dispatch({
                        type: 'UPDATE_QUANTITY',
                        payload: { productId: item.product.id, quantity: item.quantity - 1 }
                      })}
                      data-testid={`cart-qty-minus-${item.product.id}`}
                    >
                      −
                    </button>
                    <span className="cart-qty-value">{item.quantity}</span>
                    <button
                      className="cart-qty-btn"
                      onClick={() => dispatch({
                        type: 'UPDATE_QUANTITY',
                        payload: { productId: item.product.id, quantity: item.quantity + 1 }
                      })}
                      data-testid={`cart-qty-plus-${item.product.id}`}
                    >
                      +
                    </button>
                  </div>
                </div>
                <button
                  className="cart-item-remove"
                  onClick={() => dispatch({ type: 'REMOVE_FROM_CART', payload: item.product.id })}
                  data-testid={`cart-remove-${item.product.id}`}
                >
                  🗑️ Remove
                </button>
              </div>
            ))
          )}
        </div>

        {state.cart.length > 0 && (
          <div className="cart-footer">
            <div className="cart-subtotal">
              <span>Subtotal</span>
              <span>${subtotal.toFixed(2)}</span>
            </div>
            <div className="cart-subtotal">
              <span>Shipping</span>
              <span>{shipping === 0 ? 'FREE' : `$${shipping.toFixed(2)}`}</span>
            </div>
            <div className="cart-total">
              <span>Total</span>
              <span>${total.toFixed(2)}</span>
            </div>
            <button
              className="checkout-btn"
              onClick={handleCheckout}
              data-testid="checkout-btn"
            >
              Proceed to Checkout
            </button>
          </div>
        )}
      </div>
    </>
  );
}

function AuthModal() {
  const { state, dispatch, addToast } = useApp();
  const [activeTab, setActiveTab] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validateForm = () => {
    const newErrors: Record<string, string> = {};
    if (!email) newErrors.email = 'Email is required';
    else if (!/\S+@\S+\.\S+/.test(email)) newErrors.email = 'Invalid email format';
    if (!password) newErrors.password = 'Password is required';
    else if (password.length < 6) newErrors.password = 'Password must be at least 6 characters';
    if (activeTab === 'register' && !name) newErrors.name = 'Name is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);

    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1500));

    dispatch({
      type: 'SET_USER',
      payload: {
        id: '1',
        name: name || email.split('@')[0],
        email,
        avatar: ''
      }
    });
    dispatch({ type: 'SET_AUTH_MODAL_OPEN', payload: false });
    addToast('success', `Welcome${activeTab === 'register' ? '' : ' back'}, ${name || email.split('@')[0]}!`);
    setLoading(false);
    setEmail('');
    setPassword('');
    setName('');
  };

  const handleSocialLogin = async (provider: string) => {
    setLoading(true);
    await new Promise(resolve => setTimeout(resolve, 1000));
    dispatch({
      type: 'SET_USER',
      payload: { id: '1', name: `${provider} User`, email: `user@${provider.toLowerCase()}.com`, avatar: '' }
    });
    dispatch({ type: 'SET_AUTH_MODAL_OPEN', payload: false });
    addToast('success', `Signed in with ${provider}!`);
    setLoading(false);
  };

  return (
    <div
      className={`modal-overlay ${state.isAuthModalOpen ? 'open' : ''}`}
      onClick={() => dispatch({ type: 'SET_AUTH_MODAL_OPEN', payload: false })}
      data-testid="auth-modal-overlay"
    >
      <div className="modal" onClick={(e) => e.stopPropagation()} data-testid="auth-modal">
        <div className="modal-header">
          <h2>{activeTab === 'login' ? 'Welcome Back' : 'Create Account'}</h2>
          <button
            className="modal-close"
            onClick={() => dispatch({ type: 'SET_AUTH_MODAL_OPEN', payload: false })}
            data-testid="auth-modal-close"
          >
            ✕
          </button>
        </div>

        <div className="auth-tabs">
          <button
            className={`auth-tab ${activeTab === 'login' ? 'active' : ''}`}
            onClick={() => { setActiveTab('login'); setErrors({}); }}
            data-testid="auth-tab-login"
          >
            Sign In
          </button>
          <button
            className={`auth-tab ${activeTab === 'register' ? 'active' : ''}`}
            onClick={() => { setActiveTab('register'); setErrors({}); }}
            data-testid="auth-tab-register"
          >
            Register
          </button>
        </div>

        <form className="auth-form" onSubmit={handleSubmit} data-testid="auth-form">
          {activeTab === 'register' && (
            <div className="form-group">
              <label className="form-label">Full Name</label>
              <input
                type="text"
                className={`form-input ${errors.name ? 'error' : ''}`}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="John Doe"
                data-testid="auth-name-input"
              />
              {errors.name && <span className="form-error">{errors.name}</span>}
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              type="email"
              className={`form-input ${errors.email ? 'error' : ''}`}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              data-testid="auth-email-input"
            />
            {errors.email && <span className="form-error">{errors.email}</span>}
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              className={`form-input ${errors.password ? 'error' : ''}`}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              data-testid="auth-password-input"
            />
            {errors.password && <span className="form-error">{errors.password}</span>}
          </div>

          {activeTab === 'login' && (
            <div style={{ textAlign: 'right' }}>
              <button
                type="button"
                style={{ background: 'none', border: 'none', color: '#2563eb', cursor: 'pointer' }}
                data-testid="forgot-password"
              >
                Forgot password?
              </button>
            </div>
          )}

          <button
            type="submit"
            className="auth-btn"
            disabled={loading}
            data-testid="auth-submit"
          >
            {loading ? 'Please wait...' : activeTab === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>

        <div className="social-auth">
          <div className="social-divider">or continue with</div>
          <button
            className="social-btn"
            onClick={() => handleSocialLogin('Google')}
            disabled={loading}
            data-testid="social-google"
          >
            🔵 Continue with Google
          </button>
          <button
            className="social-btn"
            onClick={() => handleSocialLogin('Apple')}
            disabled={loading}
            data-testid="social-apple"
          >
            🍎 Continue with Apple
          </button>
        </div>
      </div>
    </div>
  );
}

function CheckoutPage() {
  const { state, dispatch, addToast } = useApp();
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [promoCode, setPromoCode] = useState('');
  const [discount, setDiscount] = useState(0);

  const subtotal = state.cart.reduce((sum, item) => sum + item.product.price * item.quantity, 0);
  const shipping = subtotal > 100 ? 0 : 9.99;
  const tax = subtotal * 0.08;
  const total = subtotal + shipping + tax - discount;

  const steps = ['Cart', 'Shipping', 'Payment', 'Confirmation'];

  const validateShipping = () => {
    const newErrors: Record<string, string> = {};
    const s = state.shippingInfo;
    if (!s.firstName) newErrors.firstName = 'Required';
    if (!s.lastName) newErrors.lastName = 'Required';
    if (!s.email) newErrors.email = 'Required';
    else if (!/\S+@\S+\.\S+/.test(s.email)) newErrors.email = 'Invalid email';
    if (!s.phone) newErrors.phone = 'Required';
    if (!s.address) newErrors.address = 'Required';
    if (!s.city) newErrors.city = 'Required';
    if (!s.state) newErrors.state = 'Required';
    if (!s.zip) newErrors.zip = 'Required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const validatePayment = () => {
    const newErrors: Record<string, string> = {};
    const p = state.paymentInfo;
    if (p.method === 'card') {
      if (!p.cardNumber) newErrors.cardNumber = 'Required';
      else if (p.cardNumber.replace(/\s/g, '').length !== 16) newErrors.cardNumber = 'Invalid card number';
      if (!p.expiry) newErrors.expiry = 'Required';
      if (!p.cvv) newErrors.cvv = 'Required';
      else if (p.cvv.length < 3) newErrors.cvv = 'Invalid CVV';
      if (!p.nameOnCard) newErrors.nameOnCard = 'Required';
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleContinue = async () => {
    if (state.checkoutStep === 1) {
      if (!validateShipping()) return;
      dispatch({ type: 'SET_CHECKOUT_STEP', payload: 2 });
    } else if (state.checkoutStep === 2) {
      if (!validatePayment()) return;
      setLoading(true);

      // Simulate payment processing
      await new Promise(resolve => setTimeout(resolve, 2000));

      const orderId = `ORD-${Date.now().toString(36).toUpperCase()}`;
      dispatch({ type: 'COMPLETE_ORDER', payload: orderId });
      dispatch({ type: 'SET_CHECKOUT_STEP', payload: 3 });
      addToast('success', 'Order placed successfully!');
      setLoading(false);
    }
  };

  const handleApplyPromo = () => {
    if (promoCode.toLowerCase() === 'save10') {
      setDiscount(subtotal * 0.1);
      addToast('success', 'Promo code applied! 10% off');
    } else if (promoCode.toLowerCase() === 'freeship') {
      setDiscount(shipping);
      addToast('success', 'Free shipping applied!');
    } else {
      addToast('error', 'Invalid promo code');
    }
  };

  if (state.checkoutStep === 0) return null;

  if (state.orderComplete) {
    return (
      <div className="main-content">
        <div className="confirmation-page" data-testid="order-confirmation">
          <div className="confirmation-icon">✓</div>
          <h1 className="confirmation-title">Thank You!</h1>
          <p className="order-number">Order #{state.orderId}</p>
          <div className="confirmation-details">
            <h3>Order Details</h3>
            <p>We've sent a confirmation email to {state.shippingInfo.email}</p>
            <p style={{ marginTop: '1rem' }}>
              <strong>Shipping to:</strong><br />
              {state.shippingInfo.firstName} {state.shippingInfo.lastName}<br />
              {state.shippingInfo.address}<br />
              {state.shippingInfo.city}, {state.shippingInfo.state} {state.shippingInfo.zip}
            </p>
            <button
              className="checkout-btn"
              onClick={() => dispatch({ type: 'RESET_CHECKOUT' })}
              style={{ marginTop: '2rem' }}
              data-testid="continue-shopping"
            >
              Continue Shopping
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="main-content">
      <div className="checkout-steps" data-testid="checkout-steps">
        {steps.map((step, idx) => (
          <React.Fragment key={step}>
            <div className={`step ${idx < state.checkoutStep ? 'completed' : ''} ${idx === state.checkoutStep ? 'active' : ''}`}>
              <div className="step-number">{idx < state.checkoutStep ? '✓' : idx + 1}</div>
              <span>{step}</span>
            </div>
            {idx < steps.length - 1 && (
              <div className={`step-connector ${idx < state.checkoutStep ? 'completed' : ''}`} />
            )}
          </React.Fragment>
        ))}
      </div>

      <div className="checkout-page">
        <div className="checkout-form">
          {state.checkoutStep === 1 && (
            <div data-testid="shipping-form">
              <div className="form-section">
                <h3>Contact Information</h3>
                <div className="form-row">
                  <div className="form-group">
                    <label className="form-label">First Name</label>
                    <input
                      type="text"
                      className={`form-input ${errors.firstName ? 'error' : ''}`}
                      value={state.shippingInfo.firstName}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { firstName: e.target.value } })}
                      data-testid="shipping-firstname"
                    />
                    {errors.firstName && <span className="form-error">{errors.firstName}</span>}
                  </div>
                  <div className="form-group">
                    <label className="form-label">Last Name</label>
                    <input
                      type="text"
                      className={`form-input ${errors.lastName ? 'error' : ''}`}
                      value={state.shippingInfo.lastName}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { lastName: e.target.value } })}
                      data-testid="shipping-lastname"
                    />
                    {errors.lastName && <span className="form-error">{errors.lastName}</span>}
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label className="form-label">Email</label>
                    <input
                      type="email"
                      className={`form-input ${errors.email ? 'error' : ''}`}
                      value={state.shippingInfo.email}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { email: e.target.value } })}
                      data-testid="shipping-email"
                    />
                    {errors.email && <span className="form-error">{errors.email}</span>}
                  </div>
                  <div className="form-group">
                    <label className="form-label">Phone</label>
                    <input
                      type="tel"
                      className={`form-input ${errors.phone ? 'error' : ''}`}
                      value={state.shippingInfo.phone}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { phone: e.target.value } })}
                      data-testid="shipping-phone"
                    />
                    {errors.phone && <span className="form-error">{errors.phone}</span>}
                  </div>
                </div>
              </div>

              <div className="form-section">
                <h3>Shipping Address</h3>
                <div className="form-group">
                  <label className="form-label">Address</label>
                  <input
                    type="text"
                    className={`form-input ${errors.address ? 'error' : ''}`}
                    value={state.shippingInfo.address}
                    onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { address: e.target.value } })}
                    data-testid="shipping-address"
                  />
                  {errors.address && <span className="form-error">{errors.address}</span>}
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label className="form-label">City</label>
                    <input
                      type="text"
                      className={`form-input ${errors.city ? 'error' : ''}`}
                      value={state.shippingInfo.city}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { city: e.target.value } })}
                      data-testid="shipping-city"
                    />
                    {errors.city && <span className="form-error">{errors.city}</span>}
                  </div>
                  <div className="form-group">
                    <label className="form-label">State</label>
                    <select
                      className={`form-select ${errors.state ? 'error' : ''}`}
                      value={state.shippingInfo.state}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { state: e.target.value } })}
                      data-testid="shipping-state"
                    >
                      <option value="">Select state</option>
                      <option value="CA">California</option>
                      <option value="NY">New York</option>
                      <option value="TX">Texas</option>
                      <option value="FL">Florida</option>
                      <option value="WA">Washington</option>
                    </select>
                    {errors.state && <span className="form-error">{errors.state}</span>}
                  </div>
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label className="form-label">ZIP Code</label>
                    <input
                      type="text"
                      className={`form-input ${errors.zip ? 'error' : ''}`}
                      value={state.shippingInfo.zip}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { zip: e.target.value } })}
                      data-testid="shipping-zip"
                    />
                    {errors.zip && <span className="form-error">{errors.zip}</span>}
                  </div>
                  <div className="form-group">
                    <label className="form-label">Country</label>
                    <select
                      className="form-select"
                      value={state.shippingInfo.country}
                      onChange={(e) => dispatch({ type: 'SET_SHIPPING_INFO', payload: { country: e.target.value } })}
                      data-testid="shipping-country"
                    >
                      <option value="US">United States</option>
                      <option value="CA">Canada</option>
                      <option value="UK">United Kingdom</option>
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {state.checkoutStep === 2 && (
            <div data-testid="payment-form">
              <div className="form-section">
                <h3>Payment Method</h3>
                <div className="payment-methods">
                  <label
                    className={`payment-method ${state.paymentInfo.method === 'card' ? 'selected' : ''}`}
                    data-testid="payment-method-card"
                  >
                    <input
                      type="radio"
                      name="payment"
                      checked={state.paymentInfo.method === 'card'}
                      onChange={() => dispatch({ type: 'SET_PAYMENT_INFO', payload: { method: 'card' } })}
                    />
                    <span>💳 Credit / Debit Card</span>
                    <div className="card-icons">
                      <span className="card-icon" style={{ background: '#1a1f71' }} />
                      <span className="card-icon" style={{ background: '#eb001b' }} />
                    </div>
                  </label>
                  <label
                    className={`payment-method ${state.paymentInfo.method === 'paypal' ? 'selected' : ''}`}
                    data-testid="payment-method-paypal"
                  >
                    <input
                      type="radio"
                      name="payment"
                      checked={state.paymentInfo.method === 'paypal'}
                      onChange={() => dispatch({ type: 'SET_PAYMENT_INFO', payload: { method: 'paypal' } })}
                    />
                    <span>🅿️ PayPal</span>
                  </label>
                  <label
                    className={`payment-method ${state.paymentInfo.method === 'applepay' ? 'selected' : ''}`}
                    data-testid="payment-method-applepay"
                  >
                    <input
                      type="radio"
                      name="payment"
                      checked={state.paymentInfo.method === 'applepay'}
                      onChange={() => dispatch({ type: 'SET_PAYMENT_INFO', payload: { method: 'applepay' } })}
                    />
                    <span>🍎 Apple Pay</span>
                  </label>
                </div>
              </div>

              {state.paymentInfo.method === 'card' && (
                <div className="form-section">
                  <h3>Card Details</h3>
                  <div className="form-group">
                    <label className="form-label">Card Number</label>
                    <input
                      type="text"
                      className={`form-input ${errors.cardNumber ? 'error' : ''}`}
                      placeholder="1234 5678 9012 3456"
                      value={state.paymentInfo.cardNumber}
                      onChange={(e) => {
                        const val = e.target.value.replace(/\D/g, '').slice(0, 16);
                        const formatted = val.replace(/(\d{4})/g, '$1 ').trim();
                        dispatch({ type: 'SET_PAYMENT_INFO', payload: { cardNumber: formatted } });
                      }}
                      data-testid="card-number"
                    />
                    {errors.cardNumber && <span className="form-error">{errors.cardNumber}</span>}
                  </div>
                  <div className="form-row">
                    <div className="form-group">
                      <label className="form-label">Expiry Date</label>
                      <input
                        type="text"
                        className={`form-input ${errors.expiry ? 'error' : ''}`}
                        placeholder="MM/YY"
                        value={state.paymentInfo.expiry}
                        onChange={(e) => {
                          let val = e.target.value.replace(/\D/g, '').slice(0, 4);
                          if (val.length >= 2) val = val.slice(0, 2) + '/' + val.slice(2);
                          dispatch({ type: 'SET_PAYMENT_INFO', payload: { expiry: val } });
                        }}
                        data-testid="card-expiry"
                      />
                      {errors.expiry && <span className="form-error">{errors.expiry}</span>}
                    </div>
                    <div className="form-group">
                      <label className="form-label">CVV</label>
                      <input
                        type="text"
                        className={`form-input ${errors.cvv ? 'error' : ''}`}
                        placeholder="123"
                        value={state.paymentInfo.cvv}
                        onChange={(e) => {
                          const val = e.target.value.replace(/\D/g, '').slice(0, 4);
                          dispatch({ type: 'SET_PAYMENT_INFO', payload: { cvv: val } });
                        }}
                        data-testid="card-cvv"
                      />
                      {errors.cvv && <span className="form-error">{errors.cvv}</span>}
                    </div>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Name on Card</label>
                    <input
                      type="text"
                      className={`form-input ${errors.nameOnCard ? 'error' : ''}`}
                      placeholder="John Doe"
                      value={state.paymentInfo.nameOnCard}
                      onChange={(e) => dispatch({ type: 'SET_PAYMENT_INFO', payload: { nameOnCard: e.target.value } })}
                      data-testid="card-name"
                    />
                    {errors.nameOnCard && <span className="form-error">{errors.nameOnCard}</span>}
                  </div>
                </div>
              )}

              {state.paymentInfo.method === 'paypal' && (
                <div className="form-section" style={{ textAlign: 'center', padding: '2rem' }}>
                  <p>You will be redirected to PayPal to complete your purchase.</p>
                </div>
              )}

              {state.paymentInfo.method === 'applepay' && (
                <div className="form-section" style={{ textAlign: 'center', padding: '2rem' }}>
                  <p>Click the button below to pay with Apple Pay.</p>
                </div>
              )}
            </div>
          )}

          <div className="form-actions">
            <button
              className="back-btn"
              onClick={() => dispatch({ type: 'SET_CHECKOUT_STEP', payload: state.checkoutStep - 1 })}
              data-testid="checkout-back"
            >
              Back
            </button>
            <button
              className="continue-btn"
              onClick={handleContinue}
              disabled={loading}
              data-testid="checkout-continue"
            >
              {loading ? (
                <>
                  <span className="loading-spinner" style={{ width: 20, height: 20, marginRight: '0.5rem' }} />
                  Processing...
                </>
              ) : state.checkoutStep === 2 ? `Pay $${total.toFixed(2)}` : 'Continue to Payment'}
            </button>
          </div>
        </div>

        <div className="order-summary" data-testid="order-summary">
          <h3>Order Summary</h3>
          <div className="order-items">
            {state.cart.map((item, idx) => (
              <div key={idx} className="order-item">
                <div className="order-item-image">{item.product.emoji}</div>
                <div className="order-item-info">
                  <div className="order-item-name">{item.product.name}</div>
                  <div className="order-item-quantity">Qty: {item.quantity}</div>
                </div>
                <div className="order-item-price">${(item.product.price * item.quantity).toFixed(2)}</div>
              </div>
            ))}
          </div>

          <div className="promo-code">
            <input
              type="text"
              className="promo-input"
              placeholder="Promo code"
              value={promoCode}
              onChange={(e) => setPromoCode(e.target.value)}
              data-testid="promo-code-input"
            />
            <button
              className="promo-btn"
              onClick={handleApplyPromo}
              data-testid="apply-promo"
            >
              Apply
            </button>
          </div>

          <div className="order-totals">
            <div className="order-line">
              <span>Subtotal</span>
              <span>${subtotal.toFixed(2)}</span>
            </div>
            <div className="order-line">
              <span>Shipping</span>
              <span>{shipping === 0 ? 'FREE' : `$${shipping.toFixed(2)}`}</span>
            </div>
            <div className="order-line">
              <span>Tax</span>
              <span>${tax.toFixed(2)}</span>
            </div>
            {discount > 0 && (
              <div className="order-line" style={{ color: '#22c55e' }}>
                <span>Discount</span>
                <span>-${discount.toFixed(2)}</span>
              </div>
            )}
            <div className="order-line total">
              <span>Total</span>
              <span>${total.toFixed(2)}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ToastContainer() {
  const { state, dispatch } = useApp();

  useEffect(() => {
    state.toasts.forEach(toast => {
      const timer = setTimeout(() => {
        dispatch({ type: 'REMOVE_TOAST', payload: toast.id });
      }, 3000);
      return () => clearTimeout(timer);
    });
  }, [state.toasts, dispatch]);

  return (
    <div className="toast-container" data-testid="toast-container">
      {state.toasts.map(toast => (
        <div key={toast.id} className={`toast ${toast.type}`} data-testid={`toast-${toast.id}`}>
          <span>{toast.type === 'success' ? '✓' : toast.type === 'error' ? '✕' : 'ℹ'}</span>
          <span>{toast.message}</span>
          <button
            className="toast-close"
            onClick={() => dispatch({ type: 'REMOVE_TOAST', payload: toast.id })}
          >
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}

// ============== Main App ==============
export default function Home() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [priceRange, setPriceRange] = useState<[number, number]>([0, 700]);
  const [sortBy, setSortBy] = useState('featured');
  const [inStockOnly, setInStockOnly] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null);

  const addToast = useCallback((type: Toast['type'], message: string) => {
    const id = Date.now().toString();
    dispatch({ type: 'ADD_TOAST', payload: { id, type, message } });
  }, []);

  // Filter and sort products
  let filteredProducts = products.filter(p => {
    if (selectedCategory !== 'All' && p.category !== selectedCategory) return false;
    if (p.price < priceRange[0] || p.price > priceRange[1]) return false;
    if (inStockOnly && p.stock === 0) return false;
    return true;
  });

  filteredProducts = [...filteredProducts].sort((a, b) => {
    switch (sortBy) {
      case 'price-low': return a.price - b.price;
      case 'price-high': return b.price - a.price;
      case 'rating': return b.rating - a.rating;
      case 'newest': return parseInt(b.id) - parseInt(a.id);
      default: return 0;
    }
  });

  return (
    <AppContext.Provider value={{ state, dispatch, addToast }}>
      <Header />
      <CartSidebar />
      <AuthModal />
      <ToastContainer />

      {selectedProduct && (
        <ProductDetail
          product={selectedProduct}
          onClose={() => setSelectedProduct(null)}
        />
      )}

      {state.checkoutStep > 0 ? (
        <CheckoutPage />
      ) : (
        <main className="main-content" data-testid="main-content">
          <div className="products-section">
            <ProductFilters
              selectedCategory={selectedCategory}
              setSelectedCategory={setSelectedCategory}
              priceRange={priceRange}
              setPriceRange={setPriceRange}
              sortBy={sortBy}
              setSortBy={setSortBy}
              inStockOnly={inStockOnly}
              setInStockOnly={setInStockOnly}
            />
            <div className="products-grid" data-testid="products-grid">
              {filteredProducts.map(product => (
                <ProductCard
                  key={product.id}
                  product={product}
                  onViewDetails={setSelectedProduct}
                />
              ))}
              {filteredProducts.length === 0 && (
                <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '3rem', color: '#64748b' }}>
                  <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔍</div>
                  <p>No products found matching your criteria</p>
                </div>
              )}
            </div>
          </div>
        </main>
      )}
    </AppContext.Provider>
  );
}
