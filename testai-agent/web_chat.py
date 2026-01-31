#!/usr/bin/env python3
"""
TestAI Web Chat - Browser-based Chat Interface for Human QA Agent

A clean, modern chat UI for extended testing sessions.
Uses aiohttp for a fully async web server.

Usage:
    python web_chat.py

    Then open: http://localhost:5000
"""

import asyncio
import json
import sys
from pathlib import Path
from aiohttp import web

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from human_qa import HumanQA, SessionMemory

# Global agent instance (persists across requests)
qa_agent = None


def get_agent():
    """Get or create the QA agent."""
    global qa_agent
    if qa_agent is None:
        qa_agent = HumanQA()
    return qa_agent


# ─────────────────────────────────────────────────────────────────
# HTML Template (embedded to avoid file serving complexity)
# ─────────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TestAI QA Agent - Chat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-dark: #1a1a2e;
            --bg-darker: #16162a;
            --bg-chat: #0f0f23;
            --text-primary: #e4e4e7;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent: #6366f1;
            --accent-hover: #818cf8;
            --user-bg: #3730a3;
            --agent-bg: #27272a;
            --success: #22c55e;
            --border: #27272a;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: var(--bg-darker);
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }
        .header h1 {
            font-size: 20px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-bar {
            display: flex;
            gap: 20px;
            font-size: 13px;
            color: var(--text-secondary);
        }
        .status-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
        }
        .main {
            flex: 1;
            display: flex;
            overflow: hidden;
        }
        .chat-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            max-width: 900px;
            margin: 0 auto;
            width: 100%;
        }
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        .message {
            max-width: 85%;
            padding: 14px 18px;
            border-radius: 16px;
            line-height: 1.5;
            font-size: 14px;
            animation: fadeIn 0.2s ease;
            white-space: pre-wrap;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .message.user {
            background: var(--user-bg);
            align-self: flex-end;
            border-bottom-right-radius: 4px;
        }
        .message.agent {
            background: var(--agent-bg);
            align-self: flex-start;
            border-bottom-left-radius: 4px;
        }
        .message.system {
            background: transparent;
            color: var(--text-muted);
            font-size: 13px;
            text-align: center;
            align-self: center;
        }
        .message-header {
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 500;
        }
        .message pre {
            background: rgba(0,0,0,0.4);
            padding: 12px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Fira Code', Consolas, monospace;
            font-size: 12px;
        }
        .message code {
            font-family: 'Fira Code', Consolas, monospace;
            font-size: 12px;
        }
        .message h3, .message h4 {
            font-weight: 600;
        }
        .message li {
            margin: 4px 0;
        }
        .message hr {
            opacity: 0.3;
        }
        .typing {
            display: flex;
            gap: 4px;
            padding: 14px 18px;
            background: var(--agent-bg);
            border-radius: 16px;
            align-self: flex-start;
        }
        .typing span {
            width: 8px;
            height: 8px;
            background: var(--text-muted);
            border-radius: 50%;
            animation: bounce 1.4s infinite ease-in-out;
        }
        .typing span:nth-child(1) { animation-delay: -0.32s; }
        .typing span:nth-child(2) { animation-delay: -0.16s; }
        @keyframes bounce {
            0%, 80%, 100% { transform: scale(0); }
            40% { transform: scale(1); }
        }
        .input-area {
            padding: 20px 24px;
            background: var(--bg-darker);
            border-top: 1px solid var(--border);
        }
        .input-container {
            display: flex;
            gap: 12px;
            max-width: 900px;
            margin: 0 auto;
        }
        #messageInput {
            flex: 1;
            padding: 14px 18px;
            background: var(--bg-chat);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--text-primary);
            font-size: 14px;
            resize: none;
            outline: none;
        }
        #messageInput:focus { border-color: var(--accent); }
        #messageInput::placeholder { color: var(--text-muted); }
        #sendBtn {
            padding: 14px 24px;
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }
        #sendBtn:hover { background: var(--accent-hover); }
        #sendBtn:disabled { background: var(--border); cursor: not-allowed; }
        .sidebar {
            width: 280px;
            background: var(--bg-darker);
            border-left: 1px solid var(--border);
            padding: 20px;
            overflow-y: auto;
        }
        .sidebar h3 {
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 12px;
        }
        .sidebar-section { margin-bottom: 24px; }
        .stat {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            font-size: 13px;
            border-bottom: 1px solid var(--border);
        }
        .stat-label { color: var(--text-secondary); }
        .stat-value { color: var(--text-primary); font-weight: 500; }
        .commands { display: flex; flex-direction: column; gap: 6px; }
        .command {
            font-size: 12px;
            color: var(--text-secondary);
            padding: 6px 10px;
            background: rgba(99, 102, 241, 0.1);
            border-radius: 6px;
            cursor: pointer;
        }
        .command:hover { background: rgba(99, 102, 241, 0.2); }
        .command code { color: var(--accent-hover); font-weight: 500; }
        .features-list { display: flex; flex-wrap: wrap; gap: 6px; }
        .feature-tag {
            font-size: 11px;
            padding: 4px 8px;
            background: var(--agent-bg);
            border-radius: 4px;
            color: var(--text-secondary);
        }
        @media (max-width: 900px) { .sidebar { display: none; } }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    </style>
</head>
<body>
    <header class="header">
        <h1><span>🧪</span> TestAI QA Agent</h1>
        <div class="status-bar">
            <div class="status-item">
                <div class="status-dot"></div>
                <span>Alex is online</span>
            </div>
            <div class="status-item">
                <span id="callCount">API: 0/50</span>
            </div>
        </div>
    </header>
    <main class="main">
        <div class="chat-container">
            <div class="messages" id="messages">
                <div class="message system">
                    Chat with Alex, your senior QA engineer. Ask about testing, generate test cases, or just chat!
                </div>
            </div>
            <div class="input-area">
                <div class="input-container">
                    <textarea id="messageInput" placeholder="Ask Alex anything about QA testing..." rows="1"></textarea>
                    <button id="sendBtn">Send</button>
                </div>
            </div>
        </div>
        <aside class="sidebar">
            <div class="sidebar-section">
                <h3>Session Stats</h3>
                <div class="stat"><span class="stat-label">Messages</span><span class="stat-value" id="messageCount">0</span></div>
                <div class="stat"><span class="stat-label">API Calls</span><span class="stat-value" id="apiCalls">0/50</span></div>
                <div class="stat"><span class="stat-label">Findings</span><span class="stat-value" id="findingsCount">0</span></div>
            </div>
            <div class="sidebar-section">
                <h3>Commands</h3>
                <div class="commands">
                    <div class="command" onclick="sendCommand('/test login')"><code>/test &lt;feature&gt;</code> - Generate tests</div>
                    <div class="command" onclick="sendCommand('/status')"><code>/status</code> - Show stats</div>
                    <div class="command" onclick="sendCommand('/clear')"><code>/clear</code> - Clear chat</div>
                    <div class="command" onclick="sendCommand('/forget')"><code>/forget</code> - Reset memory</div>
                </div>
            </div>
            <div class="sidebar-section">
                <h3>Features Tested</h3>
                <div class="features-list" id="featuresList"><span class="feature-tag">None yet</span></div>
            </div>
        </aside>
    </main>
    <script>
        const messagesContainer = document.getElementById('messages');
        const messageInput = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');

        messageInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 120) + 'px';
        });

        messageInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        sendBtn.addEventListener('click', sendMessage);

        async function sendMessage() {
            const message = messageInput.value.trim();
            if (!message) return;

            addMessage(message, 'user');
            messageInput.value = '';
            messageInput.style.height = 'auto';

            const typing = showTyping();
            sendBtn.disabled = true;

            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message })
                });
                const data = await response.json();
                typing.remove();
                addMessage(data.response, 'agent');
                if (data.call_count !== undefined) updateStats(data);
            } catch (error) {
                typing.remove();
                addMessage('Connection error. Please try again.', 'system');
            }

            sendBtn.disabled = false;
            messageInput.focus();
        }

        function addMessage(content, type) {
            const div = document.createElement('div');
            div.className = `message ${type}`;
            if (type === 'agent') {
                div.innerHTML = `<div class="message-header">Alex</div>${formatMarkdown(content)}`;
            } else if (type === 'user') {
                div.innerHTML = `<div class="message-header">You</div>${escapeHtml(content)}`;
            } else {
                div.textContent = content;
            }
            messagesContainer.appendChild(div);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function formatMarkdown(text) {
            // Escape HTML first but preserve structure
            text = escapeHtml(text);

            // Code blocks (```)
            text = text.replace(/```(\\w*)?\\n([\\s\\S]*?)```/g, '<pre><code>$2</code></pre>');

            // Inline code (`)
            text = text.replace(/`([^`]+)`/g, '<code style="background:rgba(99,102,241,0.2);padding:2px 6px;border-radius:4px;">$1</code>');

            // Bold (**text**)
            text = text.replace(/\\*\\*([^*]+)\\*\\*/g, '<strong style="color:#818cf8;">$1</strong>');

            // Headers (### and ##)
            text = text.replace(/^### (.+)$/gm, '<h4 style="color:#818cf8;margin:12px 0 8px;font-size:14px;">$1</h4>');
            text = text.replace(/^## (.+)$/gm, '<h3 style="color:#a78bfa;margin:14px 0 10px;font-size:15px;">$1</h3>');

            // Horizontal rules (---)
            text = text.replace(/^---$/gm, '<hr style="border:none;border-top:1px solid #3f3f46;margin:12px 0;">');

            // Bullet lists (- item)
            text = text.replace(/^- (.+)$/gm, '<li style="margin-left:16px;list-style:disc;">$1</li>');

            // Numbered lists (1. item)
            text = text.replace(/^(\\d+)\\. (.+)$/gm, '<li style="margin-left:16px;list-style:decimal;">$2</li>');

            // Line breaks
            text = text.replace(/\\n/g, '<br>');

            return text;
        }

        function showTyping() {
            const div = document.createElement('div');
            div.className = 'typing';
            div.innerHTML = '<span></span><span></span><span></span>';
            messagesContainer.appendChild(div);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            return div;
        }

        function updateStats(data) {
            document.getElementById('callCount').textContent = `API: ${data.call_count}/${data.max_calls}`;
            document.getElementById('apiCalls').textContent = `${data.call_count}/${data.max_calls}`;
            document.getElementById('messageCount').textContent = data.message_count || 0;
        }

        function sendCommand(cmd) {
            messageInput.value = cmd;
            sendMessage();
        }

        fetch('/api/status')
            .then(r => r.json())
            .then(data => {
                document.getElementById('messageCount').textContent = data.message_count;
                document.getElementById('apiCalls').textContent = `${data.call_count}/${data.max_calls}`;
                document.getElementById('callCount').textContent = `API: ${data.call_count}/${data.max_calls}`;
                document.getElementById('findingsCount').textContent = data.findings_count;
                if (data.features_tested && data.features_tested.length > 0) {
                    document.getElementById('featuresList').innerHTML =
                        data.features_tested.map(f => `<span class="feature-tag">${f}</span>`).join('');
                }
            });

        messageInput.focus();
    </script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────

async def index(request):
    """Serve the chat interface."""
    return web.Response(text=HTML_TEMPLATE, content_type='text/html')


async def chat(request):
    """Handle chat messages."""
    try:
        data = await request.json()
        user_message = data.get('message', '').strip()

        if not user_message:
            return web.json_response({'error': 'Empty message'}, status=400)

        agent = get_agent()

        # Handle special commands
        if user_message.startswith('/'):
            parts = user_message[1:].split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ''

            if cmd == 'status':
                return web.json_response({
                    'response': agent.get_status(),
                    'is_command': True
                })

            elif cmd == 'clear':
                agent.messages = []
                return web.json_response({
                    'response': 'Conversation cleared. Memory still intact.',
                    'is_command': True
                })

            elif cmd == 'forget':
                agent.memory = SessionMemory()
                agent.messages = []
                return web.json_response({
                    'response': 'Fresh start. Who are you again? 😄',
                    'is_command': True
                })

            elif cmd == 'test' and args:
                response = await agent.quick_test(args)
                return web.json_response({
                    'response': response,
                    'call_count': agent.call_count,
                    'max_calls': agent.max_calls,
                    'message_count': len(agent.messages)
                })

        # Regular chat
        response = await agent.chat(user_message)

        return web.json_response({
            'response': response,
            'session': agent.memory.get_summary(),
            'call_count': agent.call_count,
            'max_calls': agent.max_calls,
            'message_count': len(agent.messages)
        })

    except Exception as e:
        return web.json_response({'error': str(e)}, status=500)


async def status(request):
    """Get agent status."""
    agent = get_agent()

    # Get brain status
    brain_status = {'ready': False, 'chunks': 0}
    if hasattr(agent, 'brain') and agent.brain and agent.brain.is_ready:
        brain_status = {
            'ready': True,
            'chunks': agent.brain.get_status()['knowledge_chunks']
        }

    return web.json_response({
        'call_count': agent.call_count,
        'max_calls': agent.max_calls,
        'message_count': len(agent.messages),
        'session': agent.memory.get_summary(),
        'features_tested': agent.memory.context.get('features_tested', []),
        'findings_count': len(agent.memory.context.get('findings', [])),
        'brain': brain_status
    })


async def history(request):
    """Get conversation history."""
    agent = get_agent()
    return web.json_response({
        'messages': [
            {'role': m.role, 'content': m.content}
            for m in agent.messages
        ]
    })


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

def create_app():
    """Create the aiohttp application."""
    app = web.Application()
    app.router.add_get('/', index)
    app.router.add_post('/api/chat', chat)
    app.router.add_get('/api/status', status)
    app.router.add_get('/api/history', history)
    return app


if __name__ == '__main__':
    print()
    print("🧪 TestAI Web Chat")
    print("=" * 40)
    print("Starting server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    print()

    app = create_app()
    web.run_app(app, host='127.0.0.1', port=5000, print=None)
