import { useState, useRef, useEffect, createContext, useContext } from 'react';
import './App.css';

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL STATE CONTEXT - Changes propagate across components
// ═══════════════════════════════════════════════════════════════════════════════
interface AppState {
  user: { name: string; email: string; avatar: string; role: string } | null;
  notifications: Notification[];
  theme: 'light' | 'dark';
  sidebarCollapsed: boolean;
  cards: Card[];
  kanbanTasks: KanbanTask[];
  settings: Settings;
}

interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  message: string;
  read: boolean;
  timestamp: Date;
}

interface Card {
  id: string;
  title: string;
  value: number;
  change: number;
  color: string;
}

interface KanbanTask {
  id: string;
  title: string;
  description: string;
  status: 'todo' | 'in-progress' | 'review' | 'done';
  priority: 'low' | 'medium' | 'high';
  assignee: string;
}

interface Settings {
  emailNotifications: boolean;
  pushNotifications: boolean;
  darkMode: boolean;
  compactView: boolean;
  autoSave: boolean;
  language: string;
}

const AppContext = createContext<{
  state: AppState;
  dispatch: (action: AppAction) => void;
} | null>(null);

type AppAction =
  | { type: 'LOGIN'; payload: AppState['user'] }
  | { type: 'LOGOUT' }
  | { type: 'TOGGLE_THEME' }
  | { type: 'TOGGLE_SIDEBAR' }
  | { type: 'ADD_NOTIFICATION'; payload: Omit<Notification, 'id' | 'timestamp'> }
  | { type: 'MARK_NOTIFICATION_READ'; payload: string }
  | { type: 'CLEAR_NOTIFICATIONS' }
  | { type: 'ADD_CARD'; payload: Omit<Card, 'id'> }
  | { type: 'REMOVE_CARD'; payload: string }
  | { type: 'UPDATE_CARD'; payload: Card }
  | { type: 'ADD_TASK'; payload: Omit<KanbanTask, 'id'> }
  | { type: 'MOVE_TASK'; payload: { id: string; status: KanbanTask['status'] } }
  | { type: 'DELETE_TASK'; payload: string }
  | { type: 'UPDATE_SETTINGS'; payload: Partial<Settings> };

function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case 'LOGIN':
      return { ...state, user: action.payload };
    case 'LOGOUT':
      return { ...state, user: null };
    case 'TOGGLE_THEME':
      return { ...state, theme: state.theme === 'light' ? 'dark' : 'light' };
    case 'TOGGLE_SIDEBAR':
      return { ...state, sidebarCollapsed: !state.sidebarCollapsed };
    case 'ADD_NOTIFICATION':
      return {
        ...state,
        notifications: [
          { ...action.payload, id: crypto.randomUUID(), timestamp: new Date() },
          ...state.notifications,
        ],
      };
    case 'MARK_NOTIFICATION_READ':
      return {
        ...state,
        notifications: state.notifications.map((n) =>
          n.id === action.payload ? { ...n, read: true } : n
        ),
      };
    case 'CLEAR_NOTIFICATIONS':
      return { ...state, notifications: [] };
    case 'ADD_CARD':
      return {
        ...state,
        cards: [...state.cards, { ...action.payload, id: crypto.randomUUID() }],
      };
    case 'REMOVE_CARD':
      return {
        ...state,
        cards: state.cards.filter((c) => c.id !== action.payload),
      };
    case 'UPDATE_CARD':
      return {
        ...state,
        cards: state.cards.map((c) => (c.id === action.payload.id ? action.payload : c)),
      };
    case 'ADD_TASK':
      return {
        ...state,
        kanbanTasks: [...state.kanbanTasks, { ...action.payload, id: crypto.randomUUID() }],
      };
    case 'MOVE_TASK':
      return {
        ...state,
        kanbanTasks: state.kanbanTasks.map((t) =>
          t.id === action.payload.id ? { ...t, status: action.payload.status } : t
        ),
      };
    case 'DELETE_TASK':
      return {
        ...state,
        kanbanTasks: state.kanbanTasks.filter((t) => t.id !== action.payload),
      };
    case 'UPDATE_SETTINGS':
      const newSettings = { ...state.settings, ...action.payload };
      // Interconnected: darkMode affects theme
      const newTheme = newSettings.darkMode ? 'dark' : 'light';
      return { ...state, settings: newSettings, theme: newTheme };
    default:
      return state;
  }
}

const initialState: AppState = {
  user: null,
  notifications: [],
  theme: 'light',
  sidebarCollapsed: false,
  cards: [
    { id: '1', title: 'Total Revenue', value: 54232, change: 12.5, color: '#4CAF50' },
    { id: '2', title: 'Active Users', value: 2847, change: -3.2, color: '#2196F3' },
    { id: '3', title: 'Conversion Rate', value: 3.24, change: 8.1, color: '#FF9800' },
    { id: '4', title: 'Avg Session', value: 4.32, change: 2.3, color: '#9C27B0' },
  ],
  kanbanTasks: [
    { id: 'k1', title: 'Design system update', description: 'Update color palette', status: 'todo', priority: 'high', assignee: 'Alice' },
    { id: 'k2', title: 'API integration', description: 'Connect payment gateway', status: 'in-progress', priority: 'high', assignee: 'Bob' },
    { id: 'k3', title: 'User testing', description: 'Conduct usability tests', status: 'review', priority: 'medium', assignee: 'Carol' },
    { id: 'k4', title: 'Documentation', description: 'Update API docs', status: 'done', priority: 'low', assignee: 'Dave' },
  ],
  settings: {
    emailNotifications: true,
    pushNotifications: false,
    darkMode: false,
    compactView: false,
    autoSave: true,
    language: 'en',
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM HOOK
// ═══════════════════════════════════════════════════════════════════════════════
function useApp() {
  const context = useContext(AppContext);
  if (!context) throw new Error('useApp must be used within AppProvider');
  return context;
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOGIN MODAL - Authentication flow
// ═══════════════════════════════════════════════════════════════════════════════
function LoginModal({ onClose }: { onClose: () => void }) {
  const { dispatch } = useApp();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [step, setStep] = useState<'login' | 'forgot' | '2fa'>('login');
  const [otp, setOtp] = useState(['', '', '', '', '', '']);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // Simulate API call
    await new Promise((r) => setTimeout(r, 1500));

    if (email === 'test@example.com' && password === 'password123') {
      setStep('2fa');
    } else if (email && password) {
      dispatch({
        type: 'LOGIN',
        payload: { name: 'John Doe', email, avatar: '👤', role: 'Admin' },
      });
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: { type: 'success', message: 'Welcome back!', read: false },
      });
      onClose();
    } else {
      setError('Invalid credentials');
    }
    setLoading(false);
  };

  const handleOtpChange = (index: number, value: string) => {
    if (value.length > 1) return;
    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    // Auto-focus next input
    if (value && index < 5) {
      const next = document.getElementById(`otp-${index + 1}`);
      next?.focus();
    }

    // Auto-submit when complete
    if (newOtp.every((d) => d) && newOtp.join('') === '123456') {
      dispatch({
        type: 'LOGIN',
        payload: { name: 'John Doe', email, avatar: '👤', role: 'Admin' },
      });
      onClose();
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose} data-testid="login-modal">
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose} aria-label="Close modal">×</button>

        {step === 'login' && (
          <>
            <h2>Sign In</h2>
            <form onSubmit={handleLogin}>
              <div className="form-group">
                <label htmlFor="email">Email</label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  required
                  data-testid="email-input"
                />
              </div>
              <div className="form-group">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  data-testid="password-input"
                />
              </div>
              {error && <div className="error-message" role="alert">{error}</div>}
              <button type="submit" className="btn primary" disabled={loading} data-testid="login-button">
                {loading ? 'Signing in...' : 'Sign In'}
              </button>
              <button type="button" className="btn link" onClick={() => setStep('forgot')}>
                Forgot password?
              </button>
            </form>
          </>
        )}

        {step === 'forgot' && (
          <>
            <h2>Reset Password</h2>
            <p>Enter your email to receive reset instructions.</p>
            <div className="form-group">
              <input type="email" placeholder="Email address" data-testid="reset-email" />
            </div>
            <button className="btn primary" data-testid="send-reset">Send Reset Link</button>
            <button className="btn link" onClick={() => setStep('login')}>Back to login</button>
          </>
        )}

        {step === '2fa' && (
          <>
            <h2>Two-Factor Authentication</h2>
            <p>Enter the 6-digit code from your authenticator app.</p>
            <div className="otp-inputs">
              {otp.map((digit, i) => (
                <input
                  key={i}
                  id={`otp-${i}`}
                  type="text"
                  maxLength={1}
                  value={digit}
                  onChange={(e) => handleOtpChange(i, e.target.value)}
                  className="otp-input"
                  data-testid={`otp-input-${i}`}
                />
              ))}
            </div>
            <p className="hint">Hint: Code is 123456</p>
          </>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIDEBAR - Nested navigation
// ═══════════════════════════════════════════════════════════════════════════════
function Sidebar() {
  const { state, dispatch } = useApp();
  const [expandedMenus, setExpandedMenus] = useState<string[]>(['analytics']);

  const toggleMenu = (menu: string) => {
    setExpandedMenus((prev) =>
      prev.includes(menu) ? prev.filter((m) => m !== menu) : [...prev, menu]
    );
  };

  const menuItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: '📊',
      children: [],
    },
    {
      id: 'analytics',
      label: 'Analytics',
      icon: '📈',
      children: [
        { id: 'overview', label: 'Overview' },
        { id: 'reports', label: 'Reports' },
        { id: 'real-time', label: 'Real-time' },
      ],
    },
    {
      id: 'users',
      label: 'Users',
      icon: '👥',
      children: [
        { id: 'all-users', label: 'All Users' },
        { id: 'roles', label: 'Roles & Permissions' },
        { id: 'teams', label: 'Teams' },
      ],
    },
    {
      id: 'projects',
      label: 'Projects',
      icon: '📁',
      children: [
        { id: 'active', label: 'Active' },
        { id: 'archived', label: 'Archived' },
      ],
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: '⚙️',
      children: [],
    },
  ];

  return (
    <aside className={`sidebar ${state.sidebarCollapsed ? 'collapsed' : ''}`} data-testid="sidebar">
      <div className="sidebar-header">
        <span className="logo">{state.sidebarCollapsed ? 'Y' : 'YaliTest'}</span>
        <button
          className="collapse-btn"
          onClick={() => dispatch({ type: 'TOGGLE_SIDEBAR' })}
          aria-label="Toggle sidebar"
          data-testid="toggle-sidebar"
        >
          {state.sidebarCollapsed ? '→' : '←'}
        </button>
      </div>

      <nav className="sidebar-nav">
        {menuItems.map((item) => (
          <div key={item.id} className="nav-item">
            <button
              className="nav-link"
              onClick={() => item.children.length > 0 && toggleMenu(item.id)}
              data-testid={`nav-${item.id}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {!state.sidebarCollapsed && (
                <>
                  <span className="nav-label">{item.label}</span>
                  {item.children.length > 0 && (
                    <span className={`expand-icon ${expandedMenus.includes(item.id) ? 'expanded' : ''}`}>
                      ▼
                    </span>
                  )}
                </>
              )}
            </button>
            {!state.sidebarCollapsed && item.children.length > 0 && expandedMenus.includes(item.id) && (
              <div className="nav-children">
                {item.children.map((child) => (
                  <button key={child.id} className="nav-child-link" data-testid={`nav-${child.id}`}>
                    {child.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
      </nav>
    </aside>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// HEADER - With notifications dropdown
// ═══════════════════════════════════════════════════════════════════════════════
function Header({ onLoginClick }: { onLoginClick: () => void }) {
  const { state, dispatch } = useApp();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<string[]>([]);

  const unreadCount = state.notifications.filter((n) => !n.read).length;

  // Dynamic search with debounce
  useEffect(() => {
    if (searchQuery.length < 2) {
      setSearchResults([]);
      return;
    }

    const timer = setTimeout(() => {
      // Simulate search results
      const results = [
        'Dashboard Overview',
        'User Management',
        'Analytics Report',
        'Project Settings',
        'API Documentation',
      ].filter((r) => r.toLowerCase().includes(searchQuery.toLowerCase()));
      setSearchResults(results);
    }, 300);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  return (
    <header className="header" data-testid="header">
      <div className="search-container">
        <input
          type="search"
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="search-input"
          data-testid="search-input"
          aria-label="Search"
        />
        {searchResults.length > 0 && (
          <div className="search-results" data-testid="search-results">
            {searchResults.map((result, i) => (
              <button key={i} className="search-result-item" onClick={() => setSearchQuery('')}>
                {result}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="header-actions">
        <button
          className="theme-toggle"
          onClick={() => dispatch({ type: 'TOGGLE_THEME' })}
          aria-label="Toggle theme"
          data-testid="theme-toggle"
        >
          {state.theme === 'light' ? '🌙' : '☀️'}
        </button>

        <div className="notification-container">
          <button
            className="notification-btn"
            onClick={() => setShowNotifications(!showNotifications)}
            aria-label={`Notifications ${unreadCount > 0 ? `(${unreadCount} unread)` : ''}`}
            data-testid="notification-btn"
          >
            🔔
            {unreadCount > 0 && <span className="badge">{unreadCount}</span>}
          </button>

          {showNotifications && (
            <div className="dropdown notification-dropdown" data-testid="notification-dropdown">
              <div className="dropdown-header">
                <span>Notifications</span>
                <button onClick={() => dispatch({ type: 'CLEAR_NOTIFICATIONS' })} data-testid="clear-notifications">
                  Clear all
                </button>
              </div>
              {state.notifications.length === 0 ? (
                <div className="dropdown-empty">No notifications</div>
              ) : (
                state.notifications.map((n) => (
                  <div
                    key={n.id}
                    className={`notification-item ${n.read ? 'read' : 'unread'}`}
                    onClick={() => dispatch({ type: 'MARK_NOTIFICATION_READ', payload: n.id })}
                    data-testid={`notification-${n.id}`}
                  >
                    <span className={`notification-icon ${n.type}`}>
                      {n.type === 'success' ? '✓' : n.type === 'error' ? '✕' : n.type === 'warning' ? '⚠' : 'ℹ'}
                    </span>
                    <span className="notification-message">{n.message}</span>
                  </div>
                ))
              )}
            </div>
          )}
        </div>

        {state.user ? (
          <div className="profile-container">
            <button
              className="profile-btn"
              onClick={() => setShowProfile(!showProfile)}
              data-testid="profile-btn"
            >
              <span className="avatar">{state.user.avatar}</span>
              <span className="user-name">{state.user.name}</span>
            </button>

            {showProfile && (
              <div className="dropdown profile-dropdown" data-testid="profile-dropdown">
                <div className="profile-info">
                  <span className="avatar large">{state.user.avatar}</span>
                  <div>
                    <div className="user-name">{state.user.name}</div>
                    <div className="user-email">{state.user.email}</div>
                    <div className="user-role">{state.user.role}</div>
                  </div>
                </div>
                <button className="dropdown-item" data-testid="edit-profile">Edit Profile</button>
                <button className="dropdown-item" data-testid="account-settings">Account Settings</button>
                <hr />
                <button
                  className="dropdown-item danger"
                  onClick={() => dispatch({ type: 'LOGOUT' })}
                  data-testid="logout-btn"
                >
                  Sign Out
                </button>
              </div>
            )}
          </div>
        ) : (
          <button className="btn primary" onClick={onLoginClick} data-testid="login-trigger">
            Sign In
          </button>
        )}
      </div>
    </header>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS CARDS - Dynamic add/remove
// ═══════════════════════════════════════════════════════════════════════════════
function StatsCards() {
  const { state, dispatch } = useApp();
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingCard, setEditingCard] = useState<Card | null>(null);
  const [newCard, setNewCard] = useState({ title: '', value: 0, change: 0, color: '#4CAF50' });

  const handleAddCard = () => {
    if (newCard.title) {
      dispatch({ type: 'ADD_CARD', payload: newCard });
      setNewCard({ title: '', value: 0, change: 0, color: '#4CAF50' });
      setShowAddModal(false);
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: { type: 'success', message: `Card "${newCard.title}" added`, read: false },
      });
    }
  };

  const handleUpdateCard = () => {
    if (editingCard) {
      dispatch({ type: 'UPDATE_CARD', payload: editingCard });
      setEditingCard(null);
    }
  };

  return (
    <section className="stats-section" data-testid="stats-section">
      <div className="section-header">
        <h2>Dashboard Overview</h2>
        <button className="btn secondary" onClick={() => setShowAddModal(true)} data-testid="add-card-btn">
          + Add Card
        </button>
      </div>

      <div className="stats-grid">
        {state.cards.map((card) => (
          <div
            key={card.id}
            className="stat-card"
            style={{ borderLeftColor: card.color }}
            data-testid={`stat-card-${card.id}`}
          >
            <div className="stat-header">
              <span className="stat-title">{card.title}</span>
              <div className="stat-actions">
                <button
                  className="icon-btn"
                  onClick={() => setEditingCard(card)}
                  aria-label="Edit card"
                  data-testid={`edit-card-${card.id}`}
                >
                  ✏️
                </button>
                <button
                  className="icon-btn danger"
                  onClick={() => {
                    dispatch({ type: 'REMOVE_CARD', payload: card.id });
                    dispatch({
                      type: 'ADD_NOTIFICATION',
                      payload: { type: 'info', message: `Card "${card.title}" removed`, read: false },
                    });
                  }}
                  aria-label="Delete card"
                  data-testid={`delete-card-${card.id}`}
                >
                  🗑️
                </button>
              </div>
            </div>
            <div className="stat-value">
              {typeof card.value === 'number' && card.value > 1000
                ? card.value.toLocaleString()
                : card.value}
              {card.title.includes('Rate') || card.title.includes('Session') ? '%' : ''}
            </div>
            <div className={`stat-change ${card.change >= 0 ? 'positive' : 'negative'}`}>
              {card.change >= 0 ? '↑' : '↓'} {Math.abs(card.change)}% from last month
            </div>
          </div>
        ))}
      </div>

      {/* Add Card Modal */}
      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} data-testid="add-card-modal">
            <h3>Add New Card</h3>
            <div className="form-group">
              <label>Title</label>
              <input
                type="text"
                value={newCard.title}
                onChange={(e) => setNewCard({ ...newCard, title: e.target.value })}
                placeholder="Card title"
                data-testid="new-card-title"
              />
            </div>
            <div className="form-group">
              <label>Value</label>
              <input
                type="number"
                value={newCard.value}
                onChange={(e) => setNewCard({ ...newCard, value: Number(e.target.value) })}
                data-testid="new-card-value"
              />
            </div>
            <div className="form-group">
              <label>Change %</label>
              <input
                type="number"
                value={newCard.change}
                onChange={(e) => setNewCard({ ...newCard, change: Number(e.target.value) })}
                data-testid="new-card-change"
              />
            </div>
            <div className="form-group">
              <label>Color</label>
              <input
                type="color"
                value={newCard.color}
                onChange={(e) => setNewCard({ ...newCard, color: e.target.value })}
                data-testid="new-card-color"
              />
            </div>
            <div className="modal-actions">
              <button className="btn secondary" onClick={() => setShowAddModal(false)}>Cancel</button>
              <button className="btn primary" onClick={handleAddCard} data-testid="confirm-add-card">
                Add Card
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Card Modal */}
      {editingCard && (
        <div className="modal-overlay" onClick={() => setEditingCard(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} data-testid="edit-card-modal">
            <h3>Edit Card</h3>
            <div className="form-group">
              <label>Title</label>
              <input
                type="text"
                value={editingCard.title}
                onChange={(e) => setEditingCard({ ...editingCard, title: e.target.value })}
                data-testid="edit-card-title"
              />
            </div>
            <div className="form-group">
              <label>Value</label>
              <input
                type="number"
                value={editingCard.value}
                onChange={(e) => setEditingCard({ ...editingCard, value: Number(e.target.value) })}
                data-testid="edit-card-value"
              />
            </div>
            <div className="modal-actions">
              <button className="btn secondary" onClick={() => setEditingCard(null)}>Cancel</button>
              <button className="btn primary" onClick={handleUpdateCard} data-testid="confirm-edit-card">
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// KANBAN BOARD - Drag and drop
// ═══════════════════════════════════════════════════════════════════════════════
function KanbanBoard() {
  const { state, dispatch } = useApp();
  const [draggedTask, setDraggedTask] = useState<string | null>(null);
  const [showAddTask, setShowAddTask] = useState(false);
  const [newTask, setNewTask] = useState({
    title: '',
    description: '',
    priority: 'medium' as KanbanTask['priority'],
    assignee: '',
  });

  const columns: { status: KanbanTask['status']; title: string }[] = [
    { status: 'todo', title: 'To Do' },
    { status: 'in-progress', title: 'In Progress' },
    { status: 'review', title: 'Review' },
    { status: 'done', title: 'Done' },
  ];

  const handleDragStart = (taskId: string) => {
    setDraggedTask(taskId);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (status: KanbanTask['status']) => {
    if (draggedTask) {
      dispatch({ type: 'MOVE_TASK', payload: { id: draggedTask, status } });
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: { type: 'info', message: `Task moved to ${status}`, read: false },
      });
      setDraggedTask(null);
    }
  };

  const handleAddTask = () => {
    if (newTask.title) {
      dispatch({ type: 'ADD_TASK', payload: { ...newTask, status: 'todo' } });
      setNewTask({ title: '', description: '', priority: 'medium', assignee: '' });
      setShowAddTask(false);
    }
  };

  const priorityColors = { low: '#4CAF50', medium: '#FF9800', high: '#F44336' };

  return (
    <section className="kanban-section" data-testid="kanban-section">
      <div className="section-header">
        <h2>Project Board</h2>
        <button className="btn secondary" onClick={() => setShowAddTask(true)} data-testid="add-task-btn">
          + Add Task
        </button>
      </div>

      <div className="kanban-board">
        {columns.map((column) => (
          <div
            key={column.status}
            className="kanban-column"
            onDragOver={handleDragOver}
            onDrop={() => handleDrop(column.status)}
            data-testid={`kanban-column-${column.status}`}
          >
            <div className="column-header">
              <span>{column.title}</span>
              <span className="task-count">
                {state.kanbanTasks.filter((t) => t.status === column.status).length}
              </span>
            </div>
            <div className="column-tasks">
              {state.kanbanTasks
                .filter((t) => t.status === column.status)
                .map((task) => (
                  <div
                    key={task.id}
                    className={`kanban-task ${draggedTask === task.id ? 'dragging' : ''}`}
                    draggable
                    onDragStart={() => handleDragStart(task.id)}
                    data-testid={`task-${task.id}`}
                  >
                    <div className="task-header">
                      <span
                        className="priority-dot"
                        style={{ backgroundColor: priorityColors[task.priority] }}
                        title={task.priority}
                      />
                      <button
                        className="delete-task"
                        onClick={() => dispatch({ type: 'DELETE_TASK', payload: task.id })}
                        aria-label="Delete task"
                        data-testid={`delete-task-${task.id}`}
                      >
                        ×
                      </button>
                    </div>
                    <div className="task-title">{task.title}</div>
                    <div className="task-description">{task.description}</div>
                    <div className="task-assignee">
                      <span className="assignee-avatar">👤</span>
                      {task.assignee}
                    </div>
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>

      {showAddTask && (
        <div className="modal-overlay" onClick={() => setShowAddTask(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} data-testid="add-task-modal">
            <h3>Add New Task</h3>
            <div className="form-group">
              <label>Title</label>
              <input
                type="text"
                value={newTask.title}
                onChange={(e) => setNewTask({ ...newTask, title: e.target.value })}
                placeholder="Task title"
                data-testid="new-task-title"
              />
            </div>
            <div className="form-group">
              <label>Description</label>
              <textarea
                value={newTask.description}
                onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
                placeholder="Task description"
                data-testid="new-task-description"
              />
            </div>
            <div className="form-group">
              <label>Priority</label>
              <select
                value={newTask.priority}
                onChange={(e) => setNewTask({ ...newTask, priority: e.target.value as KanbanTask['priority'] })}
                data-testid="new-task-priority"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </div>
            <div className="form-group">
              <label>Assignee</label>
              <input
                type="text"
                value={newTask.assignee}
                onChange={(e) => setNewTask({ ...newTask, assignee: e.target.value })}
                placeholder="Assignee name"
                data-testid="new-task-assignee"
              />
            </div>
            <div className="modal-actions">
              <button className="btn secondary" onClick={() => setShowAddTask(false)}>Cancel</button>
              <button className="btn primary" onClick={handleAddTask} data-testid="confirm-add-task">
                Add Task
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// CANVAS CHART - Canvas rendering
// ═══════════════════════════════════════════════════════════════════════════════
function CanvasChart() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [chartType, setChartType] = useState<'line' | 'bar'>('line');

  const data = [30, 45, 28, 80, 99, 43, 65, 78, 55, 90, 72, 85];
  const labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const padding = 40;
    const chartWidth = canvas.width - padding * 2;
    const chartHeight = canvas.height - padding * 2;
    const maxValue = Math.max(...data);

    // Draw axes
    ctx.strokeStyle = '#ccc';
    ctx.beginPath();
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, canvas.height - padding);
    ctx.lineTo(canvas.width - padding, canvas.height - padding);
    ctx.stroke();

    // Draw labels
    ctx.fillStyle = '#666';
    ctx.font = '12px sans-serif';
    ctx.textAlign = 'center';

    labels.forEach((label, i) => {
      const x = padding + (i / (labels.length - 1)) * chartWidth;
      ctx.fillText(label, x, canvas.height - padding + 20);
    });

    if (chartType === 'line') {
      // Draw line chart
      ctx.strokeStyle = '#2196F3';
      ctx.lineWidth = 2;
      ctx.beginPath();

      data.forEach((value, i) => {
        const x = padding + (i / (data.length - 1)) * chartWidth;
        const y = canvas.height - padding - (value / maxValue) * chartHeight;

        if (i === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      });

      ctx.stroke();

      // Draw points
      ctx.fillStyle = '#2196F3';
      data.forEach((value, i) => {
        const x = padding + (i / (data.length - 1)) * chartWidth;
        const y = canvas.height - padding - (value / maxValue) * chartHeight;
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fill();
      });
    } else {
      // Draw bar chart
      const barWidth = chartWidth / data.length - 10;

      data.forEach((value, i) => {
        const x = padding + (i / data.length) * chartWidth + 5;
        const barHeight = (value / maxValue) * chartHeight;
        const y = canvas.height - padding - barHeight;

        ctx.fillStyle = `hsl(${(i / data.length) * 360}, 70%, 50%)`;
        ctx.fillRect(x, y, barWidth, barHeight);
      });
    }
  }, [chartType, data]);

  return (
    <section className="chart-section" data-testid="chart-section">
      <div className="section-header">
        <h2>Analytics Chart</h2>
        <div className="chart-toggle">
          <button
            className={`toggle-btn ${chartType === 'line' ? 'active' : ''}`}
            onClick={() => setChartType('line')}
            data-testid="chart-line-btn"
          >
            Line
          </button>
          <button
            className={`toggle-btn ${chartType === 'bar' ? 'active' : ''}`}
            onClick={() => setChartType('bar')}
            data-testid="chart-bar-btn"
          >
            Bar
          </button>
        </div>
      </div>
      <canvas
        ref={canvasRef}
        width={800}
        height={300}
        className="chart-canvas"
        data-testid="analytics-canvas"
      />
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA TABLE - Sorting, filtering, pagination
// ═══════════════════════════════════════════════════════════════════════════════
function DataTable() {
  const [data] = useState([
    { id: 1, name: 'Alice Johnson', email: 'alice@example.com', role: 'Admin', status: 'Active', joined: '2023-01-15' },
    { id: 2, name: 'Bob Smith', email: 'bob@example.com', role: 'User', status: 'Active', joined: '2023-02-20' },
    { id: 3, name: 'Carol Williams', email: 'carol@example.com', role: 'Editor', status: 'Inactive', joined: '2023-03-10' },
    { id: 4, name: 'David Brown', email: 'david@example.com', role: 'User', status: 'Active', joined: '2023-04-05' },
    { id: 5, name: 'Eve Davis', email: 'eve@example.com', role: 'Admin', status: 'Active', joined: '2023-05-12' },
    { id: 6, name: 'Frank Miller', email: 'frank@example.com', role: 'User', status: 'Pending', joined: '2023-06-18' },
    { id: 7, name: 'Grace Wilson', email: 'grace@example.com', role: 'Editor', status: 'Active', joined: '2023-07-22' },
    { id: 8, name: 'Henry Taylor', email: 'henry@example.com', role: 'User', status: 'Inactive', joined: '2023-08-30' },
  ]);

  const [sortField, setSortField] = useState<string>('name');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [filter, setFilter] = useState('');
  const [selectedRows, setSelectedRows] = useState<number[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage] = useState(5);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const filteredData = data.filter(
    (row) =>
      row.name.toLowerCase().includes(filter.toLowerCase()) ||
      row.email.toLowerCase().includes(filter.toLowerCase()) ||
      row.role.toLowerCase().includes(filter.toLowerCase())
  );

  const sortedData = [...filteredData].sort((a, b) => {
    const aVal = a[sortField as keyof typeof a];
    const bVal = b[sortField as keyof typeof b];
    const comparison = String(aVal).localeCompare(String(bVal));
    return sortDirection === 'asc' ? comparison : -comparison;
  });

  const paginatedData = sortedData.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage
  );

  const totalPages = Math.ceil(sortedData.length / rowsPerPage);

  const toggleSelectAll = () => {
    if (selectedRows.length === paginatedData.length) {
      setSelectedRows([]);
    } else {
      setSelectedRows(paginatedData.map((r) => r.id));
    }
  };

  const toggleRow = (id: number) => {
    setSelectedRows((prev) =>
      prev.includes(id) ? prev.filter((r) => r !== id) : [...prev, id]
    );
  };

  return (
    <section className="table-section" data-testid="table-section">
      <div className="section-header">
        <h2>User Management</h2>
        <div className="table-actions">
          <input
            type="text"
            placeholder="Filter..."
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="filter-input"
            data-testid="table-filter"
          />
          {selectedRows.length > 0 && (
            <button className="btn danger" data-testid="bulk-delete">
              Delete Selected ({selectedRows.length})
            </button>
          )}
        </div>
      </div>

      <div className="table-container">
        <table className="data-table" data-testid="data-table">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  checked={selectedRows.length === paginatedData.length && paginatedData.length > 0}
                  onChange={toggleSelectAll}
                  data-testid="select-all"
                />
              </th>
              {['name', 'email', 'role', 'status', 'joined'].map((field) => (
                <th
                  key={field}
                  onClick={() => handleSort(field)}
                  className="sortable"
                  data-testid={`sort-${field}`}
                >
                  {field.charAt(0).toUpperCase() + field.slice(1)}
                  {sortField === field && (
                    <span className="sort-indicator">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </th>
              ))}
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginatedData.map((row) => (
              <tr key={row.id} className={selectedRows.includes(row.id) ? 'selected' : ''} data-testid={`row-${row.id}`}>
                <td>
                  <input
                    type="checkbox"
                    checked={selectedRows.includes(row.id)}
                    onChange={() => toggleRow(row.id)}
                    data-testid={`select-row-${row.id}`}
                  />
                </td>
                <td>{row.name}</td>
                <td>{row.email}</td>
                <td><span className="badge role">{row.role}</span></td>
                <td>
                  <span className={`badge status ${row.status.toLowerCase()}`}>{row.status}</span>
                </td>
                <td>{row.joined}</td>
                <td>
                  <button className="icon-btn" data-testid={`edit-row-${row.id}`}>✏️</button>
                  <button className="icon-btn danger" data-testid={`delete-row-${row.id}`}>🗑️</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="pagination" data-testid="pagination">
        <button
          disabled={currentPage === 1}
          onClick={() => setCurrentPage((p) => p - 1)}
          data-testid="prev-page"
        >
          Previous
        </button>
        <span>
          Page {currentPage} of {totalPages}
        </span>
        <button
          disabled={currentPage === totalPages}
          onClick={() => setCurrentPage((p) => p + 1)}
          data-testid="next-page"
        >
          Next
        </button>
      </div>
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS PANEL - Interconnected toggles
// ═══════════════════════════════════════════════════════════════════════════════
function SettingsPanel() {
  const { state, dispatch } = useApp();
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [pendingSetting, setPendingSetting] = useState<{ key: string; value: boolean } | null>(null);

  const handleSettingChange = (key: keyof Settings, value: boolean | string) => {
    // Some settings require confirmation
    if (key === 'darkMode' || key === 'compactView') {
      setPendingSetting({ key, value: value as boolean });
      setShowConfirmModal(true);
    } else {
      dispatch({ type: 'UPDATE_SETTINGS', payload: { [key]: value } });
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: { type: 'success', message: 'Settings updated', read: false },
      });
    }
  };

  const confirmSetting = () => {
    if (pendingSetting) {
      dispatch({ type: 'UPDATE_SETTINGS', payload: { [pendingSetting.key]: pendingSetting.value } });
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: { type: 'success', message: 'Settings updated', read: false },
      });
    }
    setShowConfirmModal(false);
    setPendingSetting(null);
  };

  return (
    <section className="settings-section" data-testid="settings-section">
      <div className="section-header">
        <h2>Settings</h2>
      </div>

      <div className="settings-grid">
        <div className="settings-group">
          <h3>Notifications</h3>
          <label className="setting-row">
            <span>Email Notifications</span>
            <input
              type="checkbox"
              checked={state.settings.emailNotifications}
              onChange={(e) => handleSettingChange('emailNotifications', e.target.checked)}
              data-testid="setting-email-notifications"
            />
          </label>
          <label className="setting-row">
            <span>Push Notifications</span>
            <input
              type="checkbox"
              checked={state.settings.pushNotifications}
              onChange={(e) => handleSettingChange('pushNotifications', e.target.checked)}
              data-testid="setting-push-notifications"
            />
          </label>
        </div>

        <div className="settings-group">
          <h3>Appearance</h3>
          <label className="setting-row">
            <span>Dark Mode</span>
            <input
              type="checkbox"
              checked={state.settings.darkMode}
              onChange={(e) => handleSettingChange('darkMode', e.target.checked)}
              data-testid="setting-dark-mode"
            />
          </label>
          <label className="setting-row">
            <span>Compact View</span>
            <input
              type="checkbox"
              checked={state.settings.compactView}
              onChange={(e) => handleSettingChange('compactView', e.target.checked)}
              data-testid="setting-compact-view"
            />
          </label>
        </div>

        <div className="settings-group">
          <h3>General</h3>
          <label className="setting-row">
            <span>Auto Save</span>
            <input
              type="checkbox"
              checked={state.settings.autoSave}
              onChange={(e) => handleSettingChange('autoSave', e.target.checked)}
              data-testid="setting-auto-save"
            />
          </label>
          <label className="setting-row">
            <span>Language</span>
            <select
              value={state.settings.language}
              onChange={(e) => handleSettingChange('language', e.target.value)}
              data-testid="setting-language"
            >
              <option value="en">English</option>
              <option value="es">Spanish</option>
              <option value="fr">French</option>
              <option value="de">German</option>
              <option value="ja">Japanese</option>
            </select>
          </label>
        </div>
      </div>

      {showConfirmModal && (
        <div className="modal-overlay" onClick={() => setShowConfirmModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()} data-testid="settings-confirm-modal">
            <h3>Confirm Change</h3>
            <p>This will change the appearance of the application. Continue?</p>
            <div className="modal-actions">
              <button className="btn secondary" onClick={() => setShowConfirmModal(false)}>Cancel</button>
              <button className="btn primary" onClick={confirmSetting} data-testid="confirm-setting">
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════════════════════
function App() {
  const [state, dispatchBase] = useState(initialState);
  const [showLogin, setShowLogin] = useState(false);

  const dispatch = (action: AppAction) => {
    dispatchBase((prev) => appReducer(prev, action));
  };

  return (
    <AppContext.Provider value={{ state, dispatch }}>
      <div className={`app ${state.theme}`} data-testid="app-container">
        <Sidebar />
        <div className={`main-content ${state.sidebarCollapsed ? 'expanded' : ''}`}>
          <Header onLoginClick={() => setShowLogin(true)} />
          <main className="dashboard">
            <StatsCards />
            <CanvasChart />
            <KanbanBoard />
            <DataTable />
            <SettingsPanel />
          </main>
        </div>
        {showLogin && <LoginModal onClose={() => setShowLogin(false)} />}
      </div>
    </AppContext.Provider>
  );
}

export default App;
