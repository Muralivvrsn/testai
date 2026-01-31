"""
TestAI Agent - Web Chat Interface

A simple web-based chat interface for interacting with the QA Agent.

Usage:
    python -m testai_agent.interface.web
    
Then open http://localhost:8080 in your browser.
"""

import asyncio
import json
from pathlib import Path
from aiohttp import web
from typing import Optional

# HTML template embedded for simplicity
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TestAI Agent - QA Consultant</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e4e4e7;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            display: grid;
            grid-template-columns: 1fr 300px;
            gap: 20px;
            height: 100vh;
        }
        
        @media (max-width: 900px) {
            .container { grid-template-columns: 1fr; }
            .sidebar { display: none; }
        }
        
        .chat-panel {
            display: flex;
            flex-direction: column;
            background: rgba(255,255,255,0.05);
            border-radius: 16px;
            overflow: hidden;
        }
        
        .header {
            padding: 20px;
            background: rgba(0,0,0,0.2);
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .header h1 {
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header .subtitle {
            color: #818cf8;
            font-size: 14px;
            margin-top: 5px;
        }
        
        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
        }
        
        .message {
            margin-bottom: 16px;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .message.user {
            text-align: right;
        }
        
        .message .bubble {
            display: inline-block;
            max-width: 80%;
            padding: 12px 16px;
            border-radius: 16px;
            text-align: left;
        }
        
        .message.user .bubble {
            background: #4f46e5;
            border-bottom-right-radius: 4px;
        }
        
        .message.assistant .bubble {
            background: rgba(255,255,255,0.1);
            border-bottom-left-radius: 4px;
        }
        
        .message .name {
            font-size: 12px;
            color: #a1a1aa;
            margin-bottom: 4px;
        }
        
        .message.assistant .name {
            color: #818cf8;
        }
        
        .thinking {
            color: #818cf8;
            font-style: italic;
            font-size: 14px;
            padding: 8px 0;
        }
        
        .input-area {
            padding: 20px;
            background: rgba(0,0,0,0.2);
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        
        .input-form {
            display: flex;
            gap: 10px;
        }
        
        .input-form input {
            flex: 1;
            padding: 12px 16px;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            background: rgba(0,0,0,0.3);
            color: white;
            font-size: 16px;
        }
        
        .input-form input:focus {
            outline: none;
            border-color: #4f46e5;
        }
        
        .input-form button {
            padding: 12px 24px;
            background: #4f46e5;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.2s;
        }
        
        .input-form button:hover {
            background: #4338ca;
        }
        
        .input-form button:disabled {
            background: #3f3f46;
            cursor: not-allowed;
        }
        
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .sidebar-card {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 16px;
        }
        
        .sidebar-card h3 {
            font-size: 14px;
            color: #a1a1aa;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        
        .status-item:last-child {
            border-bottom: none;
        }
        
        .status-active { color: #22c55e; }
        .status-pending { color: #f59e0b; }
        
        .quick-actions button {
            display: block;
            width: 100%;
            padding: 10px;
            margin-bottom: 8px;
            background: rgba(255,255,255,0.1);
            border: none;
            border-radius: 8px;
            color: white;
            cursor: pointer;
            text-align: left;
            transition: background 0.2s;
        }
        
        .quick-actions button:hover {
            background: rgba(255,255,255,0.2);
        }
        
        pre {
            background: rgba(0,0,0,0.3);
            padding: 12px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 13px;
        }
        
        code {
            background: rgba(0,0,0,0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
        }
        
        strong { color: #818cf8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="chat-panel">
            <div class="header">
                <h1>🧪 TestAI Agent</h1>
                <div class="subtitle">Senior European QA Consultant • Alex</div>
            </div>
            
            <div class="messages" id="messages">
                <div class="message assistant">
                    <div class="name">Alex (QA Consultant)</div>
                    <div class="bubble">
                        Hello! I'm Alex, your Senior QA Consultant with 15+ years of experience.
                        <br><br>
                        Tell me about a feature you need to test, and I'll generate a comprehensive
                        test plan with citations from my knowledge base.
                        <br><br>
                        Examples:
                        <br>• "login page with email and password"
                        <br>• "checkout flow with credit card payment"
                        <br>• "search functionality with filters"
                    </div>
                </div>
            </div>
            
            <div class="input-area">
                <form class="input-form" id="chatForm">
                    <input type="text" id="userInput" placeholder="Describe the feature to test..." autocomplete="off">
                    <button type="submit" id="sendBtn">Send</button>
                </form>
            </div>
        </div>
        
        <div class="sidebar">
            <div class="sidebar-card">
                <h3>System Status</h3>
                <div class="status-item">
                    <span>Brain (RAG)</span>
                    <span class="status-active">● Active</span>
                </div>
                <div class="status-item">
                    <span>LLM Gateway</span>
                    <span class="status-active">● Active</span>
                </div>
                <div class="status-item">
                    <span>Cortex</span>
                    <span class="status-active">● Active</span>
                </div>
                <div class="status-item">
                    <span>Execution</span>
                    <span class="status-pending">○ Pending</span>
                </div>
            </div>
            
            <div class="sidebar-card quick-actions">
                <h3>Quick Actions</h3>
                <button onclick="sendQuick('login page')">Test Login Page</button>
                <button onclick="sendQuick('checkout with payment')">Test Checkout</button>
                <button onclick="sendQuick('search functionality')">Test Search</button>
                <button onclick="sendQuick('user registration')">Test Registration</button>
            </div>
            
            <div class="sidebar-card" id="statsCard" style="display:none;">
                <h3>Session Stats</h3>
                <div class="status-item">
                    <span>Tests Generated</span>
                    <span id="testsGenerated">0</span>
                </div>
                <div class="status-item">
                    <span>Knowledge Used</span>
                    <span id="knowledgeUsed">0 chunks</span>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const messages = document.getElementById('messages');
        const chatForm = document.getElementById('chatForm');
        const userInput = document.getElementById('userInput');
        const sendBtn = document.getElementById('sendBtn');
        const statsCard = document.getElementById('statsCard');
        
        let totalTests = 0;
        let totalKnowledge = 0;
        
        function formatMarkdown(text) {
            // Escape HTML
            text = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            
            // Bold
            text = text.replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>');
            
            // Code blocks
            text = text.replace(/```([\\s\\S]*?)```/g, '<pre>$1</pre>');
            
            // Inline code
            text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
            
            // Headers
            text = text.replace(/^### (.+)$/gm, '<h4 style="color:#818cf8;margin:12px 0 8px;">$1</h4>');
            text = text.replace(/^## (.+)$/gm, '<h3 style="color:#818cf8;margin:16px 0 8px;">$1</h3>');
            
            // Lists
            text = text.replace(/^- (.+)$/gm, '• $1<br>');
            text = text.replace(/^(\\d+)\\. (.+)$/gm, '$1. $2<br>');
            
            // Line breaks
            text = text.replace(/\\n/g, '<br>');
            
            return text;
        }
        
        function addMessage(content, isUser = false, isThinking = false) {
            const div = document.createElement('div');
            
            if (isThinking) {
                div.className = 'thinking';
                div.textContent = '💭 ' + content;
            } else {
                div.className = 'message ' + (isUser ? 'user' : 'assistant');
                div.innerHTML = `
                    <div class="name">${isUser ? 'You' : 'Alex (QA Consultant)'}</div>
                    <div class="bubble">${formatMarkdown(content)}</div>
                `;
            }
            
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
            
            return div;
        }
        
        async function sendMessage(text) {
            if (!text.trim()) return;
            
            addMessage(text, true);
            userInput.value = '';
            sendBtn.disabled = true;
            
            const thinkingDiv = addMessage('Analyzing your request...', false, true);
            
            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text })
                });
                
                const data = await response.json();
                
                // Remove thinking indicator
                thinkingDiv.remove();
                
                // Show thinking steps
                if (data.thinking && data.thinking.length > 0) {
                    for (const thought of data.thinking) {
                        addMessage(thought, false, true);
                    }
                }
                
                // Show response
                addMessage(data.response);
                
                // Update stats
                if (data.tests_generated) {
                    totalTests += data.tests_generated;
                    document.getElementById('testsGenerated').textContent = totalTests;
                }
                if (data.knowledge_used) {
                    totalKnowledge += data.knowledge_used;
                    document.getElementById('knowledgeUsed').textContent = totalKnowledge + ' chunks';
                    statsCard.style.display = 'block';
                }
                
            } catch (error) {
                thinkingDiv.remove();
                addMessage('Sorry, there was an error processing your request. Please try again.');
            }
            
            sendBtn.disabled = false;
            userInput.focus();
        }
        
        function sendQuick(text) {
            userInput.value = text;
            sendMessage(text);
        }
        
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            sendMessage(userInput.value);
        });
        
        userInput.focus();
    </script>
</body>
</html>
'''


class WebServer:
    """Simple web server for the chat interface."""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.app = web.Application()
        self.brain = None
        self.gateway = None
        self.cortex = None
        self._setup_routes()
        
    def _setup_routes(self):
        """Set up web routes."""
        self.app.router.add_get('/', self._handle_index)
        self.app.router.add_post('/api/chat', self._handle_chat)
        self.app.router.add_get('/api/status', self._handle_status)
        
    async def _handle_index(self, request):
        """Serve the main page."""
        return web.Response(text=HTML_TEMPLATE, content_type='text/html')
        
    async def _handle_chat(self, request):
        """Handle chat messages."""
        try:
            data = await request.json()
            message = data.get('message', '')
            
            if not message:
                return web.json_response({
                    'response': 'Please enter a message.',
                    'thinking': []
                })
                
            # Initialize components if needed
            if not self.cortex:
                await self._initialize_components()
                
            thinking = []
            def capture_thinking(thought):
                thinking.append(thought)
                
            # Temporarily replace thinking callback
            old_callback = self.cortex.thinking_callback
            self.cortex.thinking_callback = capture_thinking
            
            try:
                # Analyze feature
                analysis = await self.cortex.analyze_feature(message)
                
                # Get relevant knowledge
                result = self.brain.retrieve_for_feature(message)
                
                # Generate response
                response_text = self._format_analysis(analysis, result, message)
                
                return web.json_response({
                    'response': response_text,
                    'thinking': thinking,
                    'tests_generated': 0,
                    'knowledge_used': result.total_found
                })
                
            finally:
                self.cortex.thinking_callback = old_callback
                
        except Exception as e:
            return web.json_response({
                'response': f'Error: {str(e)}',
                'thinking': []
            }, status=500)
            
    async def _handle_status(self, request):
        """Handle status requests."""
        return web.json_response({
            'brain': self.brain.get_status() if self.brain else {'ready': False},
            'gateway': 'active' if self.gateway else 'inactive'
        })
        
    async def _initialize_components(self):
        """Initialize Brain, Gateway, and Cortex."""
        from ..brain.vector_store import QABrain
        from ..connectors.llm_gateway import LLMGateway, DeepSeekConnector
        from ..core.cortex import create_cortex
        
        # Initialize Brain
        self.brain = QABrain(persist_directory='/tmp/claude/qa_brain_web')
        if not self.brain.is_ready:
            brain_file = Path(__file__).parent.parent.parent / "QA_BRAIN.md"
            if brain_file.exists():
                self.brain.ingest(str(brain_file))
                
        # Initialize Gateway
        self.gateway = LLMGateway()
        self.gateway.add_provider(DeepSeekConnector(
            api_key='sk-c104455631bb433b801fc4a16042419c',
            model='deepseek-chat',
            max_calls=10
        ))
        
        # Initialize Cortex
        self.cortex = create_cortex(self.brain, self.gateway, lambda x: None)
        
    def _format_analysis(self, analysis: dict, result, feature: str) -> str:
        """Format analysis results for display."""
        lines = [
            f"## Analysis: {feature}",
            "",
            f"**Feature Type:** {analysis.get('page_type', 'general')}",
            f"**Complexity:** {analysis.get('complexity', 'medium')}",
            f"**Has Authentication:** {'Yes' if analysis.get('has_auth') else 'No'}",
            f"**Has Payment:** {'Yes' if analysis.get('has_payment') else 'No'}",
            f"**Sensitive Data:** {'Yes' if analysis.get('has_sensitive_data') else 'No'}",
            "",
            "### Relevant Knowledge Found",
            f"Found **{result.total_found}** relevant items with **{result.confidence:.0%}** confidence.",
            "",
            "### Top Sources:",
        ]
        
        for k in result.knowledge[:5]:
            lines.append(f"- {k.citation}")
            
        lines.extend([
            "",
            "---",
            "*For full test plan generation, use the CLI: `python -m testai_agent.main`*"
        ])
        
        return '\n'.join(lines)
        
    def run(self):
        """Run the web server."""
        print(f"Starting TestAI Web Interface at http://{self.host}:{self.port}")
        web.run_app(self.app, host=self.host, port=self.port)


def main():
    """Entry point for web interface."""
    server = WebServer()
    server.run()


if __name__ == "__main__":
    main()
