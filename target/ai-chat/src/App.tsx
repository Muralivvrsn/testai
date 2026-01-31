'use client';

import React, { useState, useEffect, useRef, useReducer, useCallback, createContext, useContext } from 'react';

// ============== Types ==============
interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  status: 'sending' | 'sent' | 'streaming' | 'error';
  reactions: Reaction[];
  isEditing?: boolean;
  editedAt?: Date;
  attachments?: Attachment[];
  codeBlocks?: CodeBlock[];
  threadId?: string;
  replyToId?: string;
}

interface Reaction {
  emoji: string;
  userId: string;
}

interface Attachment {
  id: string;
  name: string;
  type: string;
  size: number;
  url?: string;
}

interface CodeBlock {
  language: string;
  code: string;
}

interface Conversation {
  id: string;
  title: string;
  messages: Message[];
  createdAt: Date;
  updatedAt: Date;
  isPinned: boolean;
  model: string;
}

interface UserSettings {
  theme: 'light' | 'dark' | 'system';
  fontSize: 'small' | 'medium' | 'large';
  sendOnEnter: boolean;
  showTimestamps: boolean;
  enableSounds: boolean;
  streamingEnabled: boolean;
  selectedModel: string;
}

// ============== Context ==============
interface AppState {
  conversations: Conversation[];
  activeConversationId: string | null;
  settings: UserSettings;
  isTyping: boolean;
  isSidebarOpen: boolean;
  isSettingsOpen: boolean;
  searchQuery: string;
  connectionStatus: 'connected' | 'disconnected' | 'reconnecting';
}

type Action =
  | { type: 'ADD_CONVERSATION'; payload: Conversation }
  | { type: 'DELETE_CONVERSATION'; payload: string }
  | { type: 'SET_ACTIVE_CONVERSATION'; payload: string | null }
  | { type: 'UPDATE_CONVERSATION'; payload: { id: string; updates: Partial<Conversation> } }
  | { type: 'ADD_MESSAGE'; payload: { conversationId: string; message: Message } }
  | { type: 'UPDATE_MESSAGE'; payload: { conversationId: string; messageId: string; updates: Partial<Message> } }
  | { type: 'DELETE_MESSAGE'; payload: { conversationId: string; messageId: string } }
  | { type: 'STREAM_MESSAGE'; payload: { conversationId: string; messageId: string; chunk: string } }
  | { type: 'ADD_REACTION'; payload: { conversationId: string; messageId: string; reaction: Reaction } }
  | { type: 'REMOVE_REACTION'; payload: { conversationId: string; messageId: string; emoji: string } }
  | { type: 'SET_TYPING'; payload: boolean }
  | { type: 'UPDATE_SETTINGS'; payload: Partial<UserSettings> }
  | { type: 'TOGGLE_SIDEBAR' }
  | { type: 'SET_SETTINGS_OPEN'; payload: boolean }
  | { type: 'SET_SEARCH_QUERY'; payload: string }
  | { type: 'SET_CONNECTION_STATUS'; payload: 'connected' | 'disconnected' | 'reconnecting' }
  | { type: 'TOGGLE_PIN'; payload: string };

const initialState: AppState = {
  conversations: [],
  activeConversationId: null,
  settings: {
    theme: 'light',
    fontSize: 'medium',
    sendOnEnter: true,
    showTimestamps: true,
    enableSounds: true,
    streamingEnabled: true,
    selectedModel: 'gpt-4',
  },
  isTyping: false,
  isSidebarOpen: true,
  isSettingsOpen: false,
  searchQuery: '',
  connectionStatus: 'connected',
};

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'ADD_CONVERSATION':
      return {
        ...state,
        conversations: [action.payload, ...state.conversations],
        activeConversationId: action.payload.id,
      };

    case 'DELETE_CONVERSATION':
      const remaining = state.conversations.filter(c => c.id !== action.payload);
      return {
        ...state,
        conversations: remaining,
        activeConversationId: state.activeConversationId === action.payload
          ? (remaining[0]?.id || null)
          : state.activeConversationId,
      };

    case 'SET_ACTIVE_CONVERSATION':
      return { ...state, activeConversationId: action.payload };

    case 'UPDATE_CONVERSATION':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload.id
            ? { ...c, ...action.payload.updates, updatedAt: new Date() }
            : c
        ),
      };

    case 'ADD_MESSAGE':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload.conversationId
            ? {
              ...c,
              messages: [...c.messages, action.payload.message],
              updatedAt: new Date(),
              title: c.messages.length === 0 && action.payload.message.role === 'user'
                ? action.payload.message.content.slice(0, 30) + '...'
                : c.title,
            }
            : c
        ),
      };

    case 'UPDATE_MESSAGE':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload.conversationId
            ? {
              ...c,
              messages: c.messages.map(m =>
                m.id === action.payload.messageId
                  ? { ...m, ...action.payload.updates }
                  : m
              ),
            }
            : c
        ),
      };

    case 'DELETE_MESSAGE':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload.conversationId
            ? {
              ...c,
              messages: c.messages.filter(m => m.id !== action.payload.messageId),
            }
            : c
        ),
      };

    case 'STREAM_MESSAGE':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload.conversationId
            ? {
              ...c,
              messages: c.messages.map(m =>
                m.id === action.payload.messageId
                  ? { ...m, content: m.content + action.payload.chunk }
                  : m
              ),
            }
            : c
        ),
      };

    case 'ADD_REACTION':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload.conversationId
            ? {
              ...c,
              messages: c.messages.map(m =>
                m.id === action.payload.messageId
                  ? { ...m, reactions: [...m.reactions, action.payload.reaction] }
                  : m
              ),
            }
            : c
        ),
      };

    case 'REMOVE_REACTION':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload.conversationId
            ? {
              ...c,
              messages: c.messages.map(m =>
                m.id === action.payload.messageId
                  ? { ...m, reactions: m.reactions.filter(r => r.emoji !== action.payload.emoji) }
                  : m
              ),
            }
            : c
        ),
      };

    case 'SET_TYPING':
      return { ...state, isTyping: action.payload };

    case 'UPDATE_SETTINGS':
      return { ...state, settings: { ...state.settings, ...action.payload } };

    case 'TOGGLE_SIDEBAR':
      return { ...state, isSidebarOpen: !state.isSidebarOpen };

    case 'SET_SETTINGS_OPEN':
      return { ...state, isSettingsOpen: action.payload };

    case 'SET_SEARCH_QUERY':
      return { ...state, searchQuery: action.payload };

    case 'SET_CONNECTION_STATUS':
      return { ...state, connectionStatus: action.payload };

    case 'TOGGLE_PIN':
      return {
        ...state,
        conversations: state.conversations.map(c =>
          c.id === action.payload ? { ...c, isPinned: !c.isPinned } : c
        ),
      };

    default:
      return state;
  }
}

const AppContext = createContext<{
  state: AppState;
  dispatch: React.Dispatch<Action>;
} | null>(null);

function useApp() {
  const context = useContext(AppContext);
  if (!context) throw new Error('useApp must be used within AppProvider');
  return context;
}

// ============== AI Response Simulation ==============
const aiResponses = [
  "I'd be happy to help you with that! Let me think about this...",
  "That's an interesting question. Here's what I think...",
  "Great question! Let me break this down for you...",
  "I understand what you're asking. Here's my analysis...",
  "Let me provide you with a detailed explanation...",
];

const codeExamples = [
  {
    language: 'javascript',
    code: `function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

// Example usage
console.log(fibonacci(10)); // Output: 55`,
  },
  {
    language: 'python',
    code: `def quicksort(arr):
    if len(arr) <= 1:
        return arr
    pivot = arr[len(arr) // 2]
    left = [x for x in arr if x < pivot]
    middle = [x for x in arr if x == pivot]
    right = [x for x in arr if x > pivot]
    return quicksort(left) + middle + quicksort(right)

# Example usage
print(quicksort([3, 6, 8, 10, 1, 2, 1]))`,
  },
  {
    language: 'typescript',
    code: `interface User {
  id: string;
  name: string;
  email: string;
}

async function fetchUser(id: string): Promise<User> {
  const response = await fetch(\`/api/users/\${id}\`);
  return response.json();
}`,
  },
];

function generateAIResponse(userMessage: string): string {
  const base = aiResponses[Math.floor(Math.random() * aiResponses.length)];

  if (userMessage.toLowerCase().includes('code') || userMessage.toLowerCase().includes('example')) {
    const example = codeExamples[Math.floor(Math.random() * codeExamples.length)];
    return `${base}\n\nHere's a code example in ${example.language}:\n\n\`\`\`${example.language}\n${example.code}\n\`\`\`\n\nThis demonstrates the concept you asked about. Let me know if you need any clarification!`;
  }

  return `${base}\n\nBased on your question about "${userMessage.slice(0, 50)}...", I would suggest considering the following points:\n\n1. **First consideration**: Always start with understanding the core requirements.\n2. **Second consideration**: Break down the problem into smaller, manageable parts.\n3. **Third consideration**: Test your assumptions early and iterate.\n\nWould you like me to elaborate on any of these points?`;
}

// ============== Components ==============

function Sidebar() {
  const { state, dispatch } = useApp();
  const [isCreating, setIsCreating] = useState(false);

  const createNewChat = () => {
    const newConversation: Conversation = {
      id: `conv-${Date.now()}`,
      title: 'New Chat',
      messages: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      isPinned: false,
      model: state.settings.selectedModel,
    };
    dispatch({ type: 'ADD_CONVERSATION', payload: newConversation });
  };

  const filteredConversations = state.conversations.filter(c =>
    c.title.toLowerCase().includes(state.searchQuery.toLowerCase())
  );

  const pinnedConversations = filteredConversations.filter(c => c.isPinned);
  const unpinnedConversations = filteredConversations.filter(c => !c.isPinned);

  return (
    <aside
      className={`sidebar ${state.isSidebarOpen ? 'open' : ''}`}
      data-testid="sidebar"
    >
      <div className="sidebar-header">
        <button
          className="new-chat-btn"
          onClick={createNewChat}
          data-testid="new-chat-btn"
        >
          ➕ New Chat
        </button>
      </div>

      <div className="sidebar-search">
        <input
          type="text"
          placeholder="Search conversations..."
          value={state.searchQuery}
          onChange={(e) => dispatch({ type: 'SET_SEARCH_QUERY', payload: e.target.value })}
          className="search-input"
          data-testid="sidebar-search"
        />
      </div>

      <div className="conversations-list" data-testid="conversations-list">
        {pinnedConversations.length > 0 && (
          <>
            <div className="conversations-section-title">📌 Pinned</div>
            {pinnedConversations.map(conv => (
              <ConversationItem key={conv.id} conversation={conv} />
            ))}
          </>
        )}

        {unpinnedConversations.length > 0 && (
          <>
            {pinnedConversations.length > 0 && (
              <div className="conversations-section-title">💬 Recent</div>
            )}
            {unpinnedConversations.map(conv => (
              <ConversationItem key={conv.id} conversation={conv} />
            ))}
          </>
        )}

        {filteredConversations.length === 0 && (
          <div className="no-conversations" data-testid="no-conversations">
            <p>No conversations yet</p>
            <p style={{ fontSize: '0.85rem', opacity: 0.7 }}>
              Start a new chat to begin
            </p>
          </div>
        )}
      </div>

      <div className="sidebar-footer">
        <button
          className="settings-btn"
          onClick={() => dispatch({ type: 'SET_SETTINGS_OPEN', payload: true })}
          data-testid="settings-btn"
        >
          ⚙️ Settings
        </button>
        <div className={`connection-status ${state.connectionStatus}`} data-testid="connection-status">
          <span className="status-dot"></span>
          {state.connectionStatus}
        </div>
      </div>
    </aside>
  );
}

function ConversationItem({ conversation }: { conversation: Conversation }) {
  const { state, dispatch } = useApp();
  const [showMenu, setShowMenu] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState(conversation.title);

  const isActive = state.activeConversationId === conversation.id;

  const handleRename = () => {
    dispatch({
      type: 'UPDATE_CONVERSATION',
      payload: { id: conversation.id, updates: { title: editTitle } },
    });
    setIsEditing(false);
  };

  return (
    <div
      className={`conversation-item ${isActive ? 'active' : ''}`}
      data-testid={`conversation-${conversation.id}`}
    >
      {isEditing ? (
        <input
          type="text"
          value={editTitle}
          onChange={(e) => setEditTitle(e.target.value)}
          onBlur={handleRename}
          onKeyDown={(e) => e.key === 'Enter' && handleRename()}
          autoFocus
          className="edit-title-input"
          data-testid={`edit-title-${conversation.id}`}
        />
      ) : (
        <div
          className="conversation-content"
          onClick={() => dispatch({ type: 'SET_ACTIVE_CONVERSATION', payload: conversation.id })}
        >
          <span className="conversation-title">{conversation.title}</span>
          <span className="conversation-date">
            {new Date(conversation.updatedAt).toLocaleDateString()}
          </span>
        </div>
      )}

      <div className="conversation-actions">
        <button
          className="action-btn"
          onClick={() => setShowMenu(!showMenu)}
          data-testid={`menu-${conversation.id}`}
        >
          ⋮
        </button>
        {showMenu && (
          <div className="conversation-menu" data-testid={`menu-dropdown-${conversation.id}`}>
            <button onClick={() => { dispatch({ type: 'TOGGLE_PIN', payload: conversation.id }); setShowMenu(false); }}>
              {conversation.isPinned ? '📌 Unpin' : '📌 Pin'}
            </button>
            <button onClick={() => { setIsEditing(true); setShowMenu(false); }}>
              ✏️ Rename
            </button>
            <button
              className="delete"
              onClick={() => {
                dispatch({ type: 'DELETE_CONVERSATION', payload: conversation.id });
                setShowMenu(false);
              }}
            >
              🗑️ Delete
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function ChatArea() {
  const { state, dispatch } = useApp();
  const [inputValue, setInputValue] = useState('');
  const [isRecording, setIsRecording] = useState(false);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const activeConversation = state.conversations.find(
    c => c.id === state.activeConversationId
  );

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeConversation?.messages]);

  const generateId = () => `msg-${Date.now()}-${Math.random().toString(36).slice(2)}`;

  const simulateStreaming = async (conversationId: string, messageId: string, fullResponse: string) => {
    dispatch({ type: 'SET_TYPING', payload: true });

    // Simulate streaming by adding chunks
    const words = fullResponse.split(' ');
    for (let i = 0; i < words.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 30 + Math.random() * 50));
      dispatch({
        type: 'STREAM_MESSAGE',
        payload: { conversationId, messageId, chunk: (i > 0 ? ' ' : '') + words[i] },
      });
    }

    dispatch({
      type: 'UPDATE_MESSAGE',
      payload: { conversationId, messageId, updates: { status: 'sent' } },
    });
    dispatch({ type: 'SET_TYPING', payload: false });
  };

  const sendMessage = async () => {
    if (!inputValue.trim() && attachments.length === 0) return;
    if (!state.activeConversationId) {
      // Create new conversation
      const newConversation: Conversation = {
        id: `conv-${Date.now()}`,
        title: inputValue.slice(0, 30) + '...',
        messages: [],
        createdAt: new Date(),
        updatedAt: new Date(),
        isPinned: false,
        model: state.settings.selectedModel,
      };
      dispatch({ type: 'ADD_CONVERSATION', payload: newConversation });

      // Wait for state update
      await new Promise(resolve => setTimeout(resolve, 0));
    }

    const conversationId = state.activeConversationId || `conv-${Date.now()}`;

    // Add user message
    const userMessage: Message = {
      id: generateId(),
      role: 'user',
      content: inputValue,
      timestamp: new Date(),
      status: 'sent',
      reactions: [],
      attachments: attachments.length > 0 ? attachments : undefined,
    };

    dispatch({ type: 'ADD_MESSAGE', payload: { conversationId, message: userMessage } });
    setInputValue('');
    setAttachments([]);

    // Simulate AI response
    const aiMessageId = generateId();
    const aiMessage: Message = {
      id: aiMessageId,
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      status: 'streaming',
      reactions: [],
    };

    dispatch({ type: 'ADD_MESSAGE', payload: { conversationId, message: aiMessage } });

    // Generate and stream response
    const fullResponse = generateAIResponse(inputValue);

    if (state.settings.streamingEnabled) {
      await simulateStreaming(conversationId, aiMessageId, fullResponse);
    } else {
      await new Promise(resolve => setTimeout(resolve, 1000));
      dispatch({
        type: 'UPDATE_MESSAGE',
        payload: {
          conversationId,
          messageId: aiMessageId,
          updates: { content: fullResponse, status: 'sent' },
        },
      });
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey && state.settings.sendOnEnter) {
      e.preventDefault();
      sendMessage();
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    const newAttachments: Attachment[] = files.map(file => ({
      id: `att-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      name: file.name,
      type: file.type,
      size: file.size,
    }));
    setAttachments(prev => [...prev, ...newAttachments]);
  };

  const removeAttachment = (id: string) => {
    setAttachments(prev => prev.filter(a => a.id !== id));
  };

  const toggleVoiceRecording = () => {
    setIsRecording(!isRecording);
    if (!isRecording) {
      // Simulate voice recording
      setTimeout(() => {
        setInputValue(prev => prev + ' [Voice transcription: Hello, I have a question about...]');
        setIsRecording(false);
      }, 2000);
    }
  };

  if (!activeConversation && state.conversations.length === 0) {
    return (
      <div className="chat-area empty" data-testid="chat-area-empty">
        <div className="empty-state">
          <div className="empty-icon">🤖</div>
          <h2>Welcome to AI Assistant</h2>
          <p>Start a new conversation to begin chatting with AI</p>
          <button
            className="start-chat-btn"
            onClick={() => {
              const newConversation: Conversation = {
                id: `conv-${Date.now()}`,
                title: 'New Chat',
                messages: [],
                createdAt: new Date(),
                updatedAt: new Date(),
                isPinned: false,
                model: state.settings.selectedModel,
              };
              dispatch({ type: 'ADD_CONVERSATION', payload: newConversation });
            }}
            data-testid="start-chat-btn"
          >
            Start New Chat
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="chat-area" data-testid="chat-area">
      <div className="chat-header" data-testid="chat-header">
        <button
          className="toggle-sidebar-btn"
          onClick={() => dispatch({ type: 'TOGGLE_SIDEBAR' })}
          data-testid="toggle-sidebar"
        >
          ☰
        </button>
        <div className="chat-title">
          <h2>{activeConversation?.title || 'New Chat'}</h2>
          <span className="model-badge" data-testid="model-badge">
            {state.settings.selectedModel}
          </span>
        </div>
        <div className="chat-actions">
          <button className="action-btn" data-testid="export-btn" title="Export chat">
            📥
          </button>
          <button className="action-btn" data-testid="share-btn" title="Share chat">
            🔗
          </button>
        </div>
      </div>

      <div className="messages-container" data-testid="messages-container">
        {activeConversation?.messages.map(message => (
          <MessageBubble
            key={message.id}
            message={message}
            conversationId={activeConversation.id}
          />
        ))}

        {state.isTyping && (
          <div className="typing-indicator" data-testid="typing-indicator">
            <div className="typing-dots">
              <span></span>
              <span></span>
              <span></span>
            </div>
            <span>AI is typing...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <div className="input-area" data-testid="input-area">
        {attachments.length > 0 && (
          <div className="attachments-preview" data-testid="attachments-preview">
            {attachments.map(att => (
              <div key={att.id} className="attachment-item">
                <span>📎 {att.name}</span>
                <button onClick={() => removeAttachment(att.id)}>✕</button>
              </div>
            ))}
          </div>
        )}

        <div className="input-container">
          <button
            className="attach-btn"
            onClick={() => fileInputRef.current?.click()}
            data-testid="attach-btn"
          >
            📎
          </button>
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileSelect}
            multiple
            style={{ display: 'none' }}
            data-testid="file-input"
          />

          <textarea
            ref={textareaRef}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type your message..."
            className="message-input"
            rows={1}
            data-testid="message-input"
          />

          <button
            className={`voice-btn ${isRecording ? 'recording' : ''}`}
            onClick={toggleVoiceRecording}
            data-testid="voice-btn"
          >
            🎤
          </button>

          <button
            className="send-btn"
            onClick={sendMessage}
            disabled={!inputValue.trim() && attachments.length === 0}
            data-testid="send-btn"
          >
            ➤
          </button>
        </div>

        <div className="input-footer">
          <span className="char-count" data-testid="char-count">
            {inputValue.length} / 4000
          </span>
          <span className="hint">
            {state.settings.sendOnEnter ? 'Press Enter to send, Shift+Enter for new line' : 'Click send button to send'}
          </span>
        </div>
      </div>
    </div>
  );
}

function MessageBubble({ message, conversationId }: { message: Message; conversationId: string }) {
  const { state, dispatch } = useApp();
  const [isEditing, setIsEditing] = useState(false);
  const [editContent, setEditContent] = useState(message.content);
  const [showReactions, setShowReactions] = useState(false);
  const [showActions, setShowActions] = useState(false);

  const reactions = ['👍', '👎', '❤️', '😂', '🤔', '🎉'];

  const handleEdit = () => {
    dispatch({
      type: 'UPDATE_MESSAGE',
      payload: {
        conversationId,
        messageId: message.id,
        updates: { content: editContent, editedAt: new Date() },
      },
    });
    setIsEditing(false);
  };

  const handleReaction = (emoji: string) => {
    const hasReaction = message.reactions.some(r => r.emoji === emoji);
    if (hasReaction) {
      dispatch({
        type: 'REMOVE_REACTION',
        payload: { conversationId, messageId: message.id, emoji },
      });
    } else {
      dispatch({
        type: 'ADD_REACTION',
        payload: {
          conversationId,
          messageId: message.id,
          reaction: { emoji, userId: 'user-1' },
        },
      });
    }
    setShowReactions(false);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(message.content);
  };

  const formatContent = (content: string) => {
    // Simple markdown-like formatting
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
    const parts: React.ReactNode[] = [];
    let lastIndex = 0;
    let match;

    while ((match = codeBlockRegex.exec(content)) !== null) {
      // Add text before code block
      if (match.index > lastIndex) {
        parts.push(
          <span key={lastIndex}>{content.slice(lastIndex, match.index)}</span>
        );
      }

      // Add code block
      const language = match[1] || 'text';
      const code = match[2];
      parts.push(
        <div key={match.index} className="code-block" data-testid="code-block">
          <div className="code-header">
            <span>{language}</span>
            <button onClick={() => navigator.clipboard.writeText(code)} data-testid="copy-code">
              📋 Copy
            </button>
          </div>
          <pre><code>{code}</code></pre>
        </div>
      );

      lastIndex = match.index + match[0].length;
    }

    // Add remaining text
    if (lastIndex < content.length) {
      parts.push(<span key={lastIndex}>{content.slice(lastIndex)}</span>);
    }

    return parts.length > 0 ? parts : content;
  };

  return (
    <div
      className={`message ${message.role}`}
      data-testid={`message-${message.id}`}
      onMouseEnter={() => setShowActions(true)}
      onMouseLeave={() => setShowActions(false)}
    >
      <div className="message-avatar">
        {message.role === 'user' ? '👤' : '🤖'}
      </div>

      <div className="message-content">
        <div className="message-header">
          <span className="message-role">{message.role === 'user' ? 'You' : 'AI Assistant'}</span>
          {state.settings.showTimestamps && (
            <span className="message-time">
              {new Date(message.timestamp).toLocaleTimeString()}
            </span>
          )}
          {message.editedAt && <span className="edited-badge">(edited)</span>}
        </div>

        {isEditing ? (
          <div className="edit-container">
            <textarea
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              className="edit-textarea"
              data-testid="edit-textarea"
            />
            <div className="edit-actions">
              <button onClick={handleEdit} data-testid="save-edit">Save</button>
              <button onClick={() => setIsEditing(false)} data-testid="cancel-edit">Cancel</button>
            </div>
          </div>
        ) : (
          <div className="message-text">
            {message.status === 'streaming' && !message.content && (
              <span className="cursor-blink">▊</span>
            )}
            {formatContent(message.content)}
            {message.status === 'streaming' && message.content && (
              <span className="cursor-blink">▊</span>
            )}
          </div>
        )}

        {message.attachments && message.attachments.length > 0 && (
          <div className="message-attachments">
            {message.attachments.map(att => (
              <div key={att.id} className="attachment" data-testid={`attachment-${att.id}`}>
                📎 {att.name} ({(att.size / 1024).toFixed(1)} KB)
              </div>
            ))}
          </div>
        )}

        {message.reactions.length > 0 && (
          <div className="message-reactions" data-testid="message-reactions">
            {message.reactions.map((r, idx) => (
              <span
                key={idx}
                className="reaction"
                onClick={() => handleReaction(r.emoji)}
              >
                {r.emoji}
              </span>
            ))}
          </div>
        )}

        {showActions && message.status !== 'streaming' && (
          <div className="message-actions" data-testid={`actions-${message.id}`}>
            <button onClick={copyToClipboard} title="Copy" data-testid="copy-message">
              📋
            </button>
            {message.role === 'user' && (
              <button onClick={() => setIsEditing(true)} title="Edit" data-testid="edit-message">
                ✏️
              </button>
            )}
            <button
              onClick={() => setShowReactions(!showReactions)}
              title="React"
              data-testid="react-message"
            >
              😊
            </button>
            <button
              onClick={() => dispatch({ type: 'DELETE_MESSAGE', payload: { conversationId, messageId: message.id } })}
              title="Delete"
              data-testid="delete-message"
            >
              🗑️
            </button>
          </div>
        )}

        {showReactions && (
          <div className="reactions-picker" data-testid="reactions-picker">
            {reactions.map(emoji => (
              <button
                key={emoji}
                onClick={() => handleReaction(emoji)}
                className={message.reactions.some(r => r.emoji === emoji) ? 'active' : ''}
              >
                {emoji}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SettingsModal() {
  const { state, dispatch } = useApp();

  if (!state.isSettingsOpen) return null;

  const models = ['gpt-4', 'gpt-3.5-turbo', 'claude-3', 'claude-2', 'llama-2'];
  const themes = ['light', 'dark', 'system'];
  const fontSizes = ['small', 'medium', 'large'];

  return (
    <div
      className="modal-overlay"
      onClick={() => dispatch({ type: 'SET_SETTINGS_OPEN', payload: false })}
      data-testid="settings-overlay"
    >
      <div className="settings-modal" onClick={e => e.stopPropagation()} data-testid="settings-modal">
        <div className="settings-header">
          <h2>Settings</h2>
          <button
            onClick={() => dispatch({ type: 'SET_SETTINGS_OPEN', payload: false })}
            className="close-btn"
            data-testid="close-settings"
          >
            ✕
          </button>
        </div>

        <div className="settings-content">
          <div className="settings-section">
            <h3>Appearance</h3>
            <div className="setting-item">
              <label>Theme</label>
              <select
                value={state.settings.theme}
                onChange={(e) => dispatch({ type: 'UPDATE_SETTINGS', payload: { theme: e.target.value as any } })}
                data-testid="theme-select"
              >
                {themes.map(t => (
                  <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                ))}
              </select>
            </div>
            <div className="setting-item">
              <label>Font Size</label>
              <select
                value={state.settings.fontSize}
                onChange={(e) => dispatch({ type: 'UPDATE_SETTINGS', payload: { fontSize: e.target.value as any } })}
                data-testid="font-size-select"
              >
                {fontSizes.map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="settings-section">
            <h3>Model</h3>
            <div className="setting-item">
              <label>Selected Model</label>
              <select
                value={state.settings.selectedModel}
                onChange={(e) => dispatch({ type: 'UPDATE_SETTINGS', payload: { selectedModel: e.target.value } })}
                data-testid="model-select"
              >
                {models.map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
            </div>
            <div className="setting-item toggle">
              <label>Enable Streaming</label>
              <button
                className={`toggle-btn ${state.settings.streamingEnabled ? 'active' : ''}`}
                onClick={() => dispatch({ type: 'UPDATE_SETTINGS', payload: { streamingEnabled: !state.settings.streamingEnabled } })}
                data-testid="streaming-toggle"
              >
                <span className="toggle-knob"></span>
              </button>
            </div>
          </div>

          <div className="settings-section">
            <h3>Behavior</h3>
            <div className="setting-item toggle">
              <label>Send on Enter</label>
              <button
                className={`toggle-btn ${state.settings.sendOnEnter ? 'active' : ''}`}
                onClick={() => dispatch({ type: 'UPDATE_SETTINGS', payload: { sendOnEnter: !state.settings.sendOnEnter } })}
                data-testid="send-enter-toggle"
              >
                <span className="toggle-knob"></span>
              </button>
            </div>
            <div className="setting-item toggle">
              <label>Show Timestamps</label>
              <button
                className={`toggle-btn ${state.settings.showTimestamps ? 'active' : ''}`}
                onClick={() => dispatch({ type: 'UPDATE_SETTINGS', payload: { showTimestamps: !state.settings.showTimestamps } })}
                data-testid="timestamps-toggle"
              >
                <span className="toggle-knob"></span>
              </button>
            </div>
            <div className="setting-item toggle">
              <label>Enable Sounds</label>
              <button
                className={`toggle-btn ${state.settings.enableSounds ? 'active' : ''}`}
                onClick={() => dispatch({ type: 'UPDATE_SETTINGS', payload: { enableSounds: !state.settings.enableSounds } })}
                data-testid="sounds-toggle"
              >
                <span className="toggle-knob"></span>
              </button>
            </div>
          </div>

          <div className="settings-section">
            <h3>Data</h3>
            <button
              className="danger-btn"
              onClick={() => {
                if (confirm('Are you sure you want to delete all conversations?')) {
                  state.conversations.forEach(c => {
                    dispatch({ type: 'DELETE_CONVERSATION', payload: c.id });
                  });
                }
              }}
              data-testid="clear-all-btn"
            >
              🗑️ Clear All Conversations
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============== Main App ==============
export default function App() {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Apply theme
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', state.settings.theme);
  }, [state.settings.theme]);

  // Apply font size
  useEffect(() => {
    document.documentElement.setAttribute('data-font-size', state.settings.fontSize);
  }, [state.settings.fontSize]);

  // Simulate connection status changes
  useEffect(() => {
    const interval = setInterval(() => {
      const statuses: ('connected' | 'disconnected' | 'reconnecting')[] = ['connected', 'connected', 'connected', 'reconnecting'];
      const newStatus = statuses[Math.floor(Math.random() * statuses.length)];
      if (newStatus !== state.connectionStatus) {
        dispatch({ type: 'SET_CONNECTION_STATUS', payload: newStatus });
        if (newStatus === 'reconnecting') {
          setTimeout(() => {
            dispatch({ type: 'SET_CONNECTION_STATUS', payload: 'connected' });
          }, 2000);
        }
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [state.connectionStatus]);

  return (
    <AppContext.Provider value={{ state, dispatch }}>
      <div className="app" data-testid="app">
        <Sidebar />
        <ChatArea />
        <SettingsModal />
      </div>
    </AppContext.Provider>
  );
}
