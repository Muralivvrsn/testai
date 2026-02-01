/**
 * AI Agent - Full integration with testai-agent
 * Citation-aware reasoning with QA knowledge base
 * ~450 lines
 */

const { AGENT_LIMITS } = require('./config')
const { isQuestion, extractKeywords, findMatchingElements, sleep, detectPageType } = require('./utils')
const { getPageState, formatElementsForAI } = require('./dom-extractor')
const { callDeepSeek, isApiConfigured } = require('./api')
const { executeAction, shouldStopAfterAction } = require('./actions')
const { getThinkingPhrase } = require('./personality')
const { BROWSER_AGENT_PERSONA, QA_AGENT_PERSONA, getPageTypeHint } = require('./prompts')
const { getKnowledgeForPageType, formatKnowledgeForPrompt, getEdgeCases } = require('./knowledge')

/**
 * Reasoning phases (ported from cortex/reasoner.py)
 */
const ReasoningPhase = {
  UNDERSTANDING: 'understanding',
  RETRIEVING: 'retrieving',
  PLANNING: 'planning',
  GENERATING: 'generating',
  EXECUTING: 'executing',
  VALIDATING: 'validating'
}

/**
 * Check if user's question is already answered by current page
 */
function checkIfAnswered(userMessage, pageState) {
  if (!isQuestion(userMessage)) {
    return { isQuestion: false, answered: false }
  }

  const keywords = extractKeywords(userMessage)
  const matching = findMatchingElements(pageState.elements, userMessage)

  const visibleText = (pageState.visibleText || '').toLowerCase()
  const textMatches = keywords.filter(kw => visibleText.includes(kw))

  const answered = matching.length > 0 || textMatches.length >= 2

  return {
    isQuestion: true,
    answered,
    matchingElements: matching,
    textMatches
  }
}

/**
 * Get relevant QA knowledge for page
 */
function retrieveKnowledge(pageType, userMessage) {
  const sections = getKnowledgeForPageType(pageType)
  const formatted = formatKnowledgeForPrompt(sections)

  // Get page-specific hints
  const hint = getPageTypeHint(pageType)

  return {
    sections,
    formatted,
    hint,
    hasKnowledge: sections.length > 0
  }
}

/**
 * Calculate confidence score
 */
function calculateConfidence(pageState, knowledge, actionHistory) {
  let score = 0

  // Page loaded?
  if (pageState.hasPage) score += 20

  // Elements found?
  if (pageState.elements.length > 0) score += 20

  // Has knowledge?
  if (knowledge.hasKnowledge) score += 30

  // Previous actions successful?
  const successRate = actionHistory.length > 0
    ? actionHistory.filter(a => !a.result.startsWith('FAILED')).length / actionHistory.length
    : 1
  score += successRate * 30

  return {
    score: score / 100,
    level: score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low',
    canProceed: score >= 50
  }
}

/**
 * Check if user wants autonomous exploration/analysis
 */
function isExplorationRequest(message) {
  return /analy[sz]e|explore|test|check|audit|review|inspect|examine|look around|what.*(see|find)|tell me about/i.test(message)
}

/**
 * Build decision prompt - SIMPLE and ACTION-ORIENTED
 */
function buildDecisionPrompt(userMessage, pageState, actionHistory, iteration, maxIterations, knowledge) {
  const elementsForAI = formatElementsForAI(pageState.elements, 50)

  const historyText = actionHistory.length > 0
    ? `\nPREVIOUS ACTIONS:\n${actionHistory.map((a, i) => `${i + 1}. ${a.action}: ${a.result}`).join('\n')}`
    : ''

  // Only include knowledge if user is asking about TESTING
  const isTestingRequest = /test|generate|qa|quality|check|validate|verify/i.test(userMessage)
  const knowledgeSection = isTestingRequest ? `\nQA KNOWLEDGE:\n${knowledge.formatted}` : ''

  return `USER WANTS: "${userMessage}"

PAGE: ${pageState.url}
${historyText}

AVAILABLE ELEMENTS:
${JSON.stringify(elementsForAI, null, 2)}
${knowledgeSection}

WHAT TO DO - Return JSON:

To CLICK something:
{ "action": "click", "elementId": "testai-X" }

To TYPE text:
{ "action": "type", "elementId": "testai-X", "value": "text to type" }

To SCROLL:
{ "action": "scroll", "direction": "down" }

When DONE:
{ "action": "task_complete", "summary": "what you did" }

If element NOT FOUND:
{ "action": "cannot_proceed", "reason": "element not found" }

---
**RULE: DO IT FIRST. Don't ask questions. Don't explain. Just click/type.**

User said "${userMessage}" - find matching element and interact with it NOW.
Return ONLY JSON.`
}

/**
 * Autonomous page analysis - like a curious QA engineer
 */
async function analyzePageAutonomously(browserView, sendMessage) {
  sendMessage?.('thinking', '🔍 Exploring the page like a QA engineer...')

  const pageState = await getPageState(browserView)
  const pageType = detectPageType(pageState.url, pageState.elements)

  // Categorize all elements
  const buttons = pageState.elements.filter(e => e.category === 'button')
  const inputs = pageState.elements.filter(e => e.category === 'text-input')
  const links = pageState.elements.filter(e => e.category === 'link')
  const dropdowns = pageState.elements.filter(e => e.category === 'dropdown')

  // Check for potential issues
  const issues = []

  // Check for inputs without labels
  const unlabeledInputs = inputs.filter(i => !i.label && !i.placeholder)
  if (unlabeledInputs.length > 0) {
    issues.push(`⚠️ ${unlabeledInputs.length} input field(s) without labels (accessibility issue)`)
  }

  // Check for buttons without text
  const emptyButtons = buttons.filter(b => !b.text && !b.label)
  if (emptyButtons.length > 0) {
    issues.push(`⚠️ ${emptyButtons.length} button(s) without text (accessibility issue)`)
  }

  // Check for links without href or text
  const badLinks = links.filter(l => !l.href || !l.text)
  if (badLinks.length > 0) {
    issues.push(`⚠️ ${badLinks.length} link(s) missing href or text`)
  }

  // Build detailed analysis
  const analysis = {
    url: pageState.url,
    title: pageState.title,
    pageType,
    elements: {
      total: pageState.elements.length,
      buttons: buttons.length,
      inputs: inputs.length,
      links: links.length,
      dropdowns: dropdowns.length
    },
    keyButtons: buttons.slice(0, 8).map(b => b.text || b.label).filter(Boolean),
    keyInputs: inputs.slice(0, 5).map(i => i.label || i.placeholder || i.name).filter(Boolean),
    keyLinks: links.slice(0, 8).map(l => l.text).filter(Boolean),
    issues,
    hasAuth: pageState.elements.some(e => e.type === 'password' || /login|sign|auth/i.test(e.text || '')),
    hasForms: inputs.length > 0,
    hasNavigation: links.length > 5
  }

  return analysis
}

/**
 * Main agent loop with citation-aware reasoning
 */
async function runAgentLoop(browserView, viewBounds, userMessage, sendMessage) {
  if (!isApiConfigured()) {
    return {
      success: false,
      error: 'API key not configured. Please add your DeepSeek API key in Settings.'
    }
  }

  // Check if this is a navigation request - extract URL
  const urlMatch = userMessage.match(/https?:\/\/[^\s]+|[\w.-]+\.(com|org|net|io|dev|co|app)[^\s]*/i)
  const navigateMatch = userMessage.match(/(?:go to|load|open|navigate to|visit)\s+(.+)/i)

  console.log('Agent - URL match:', urlMatch?.[0])
  console.log('Agent - Navigate match:', navigateMatch?.[1])

  // If no browser but user wants to navigate, we need the browser to be created first
  if (!browserView) {
    return {
      success: false,
      error: 'Browser not ready. Please try again.'
    }
  }

  const actionHistory = []
  const thinkingSteps = []
  let iteration = 0
  let finalResponse = ''

  try {
    // Phase 1: Understanding
    thinkingSteps.push(`💭 ${ReasoningPhase.UNDERSTANDING}: Parsing request...`)
    sendMessage?.('thinking', getThinkingPhrase('receiving'))

    while (iteration < AGENT_LIMITS.maxIterations) {
    iteration++

    // Phase 2: Get fresh DOM state
    thinkingSteps.push(`💭 ${ReasoningPhase.RETRIEVING}: Getting current page state...`)
    sendMessage?.('thinking', `Step ${iteration}: ${getThinkingPhrase('analyzing')}`)

    const pageState = await getPageState(browserView)
    console.log('Page state - hasPage:', pageState.hasPage, 'url:', pageState.url)

    // If no page loaded, check if user wants to navigate
    if (!pageState.hasPage) {
      // Extract URL from message
      const urlMatch = userMessage.match(/https?:\/\/[^\s]+|[\w.-]+\.(com|org|net|io|dev|co|app)[^\s]*/i)
      const navigateMatch = userMessage.match(/(?:go to|load|open|navigate to|visit)\s+(.+)/i)

      let targetUrl = urlMatch?.[0] || navigateMatch?.[1]?.trim()

      if (targetUrl) {
        // User wants to navigate - do it!
        console.log('Navigating to:', targetUrl)
        sendMessage?.('action', `Navigating to ${targetUrl}...`)

        // Normalize URL
        if (!/^https?:\/\//i.test(targetUrl)) {
          const isLocal = targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1')
          targetUrl = (isLocal ? 'http://' : 'https://') + targetUrl
        }

        try {
          await browserView.webContents.loadURL(targetUrl)
          await sleep(2000) // Wait for page to load

          return {
            success: true,
            response: `Navigated to ${targetUrl}. What would you like me to do on this page?`,
            actionsTaken: 1,
            thinking: thinkingSteps.join('\n')
          }
        } catch (navErr) {
          return {
            success: false,
            error: `Failed to load ${targetUrl}: ${navErr.message}`,
            thinking: thinkingSteps.join('\n')
          }
        }
      }

      // No URL found and no page loaded
      return {
        success: false,
        error: 'No page loaded. Navigate to a page first or tell me a URL to visit.',
        thinking: thinkingSteps.join('\n')
      }
    }

    // Log what we found on the page
    console.log('=== PAGE ANALYSIS ===')
    console.log('URL:', pageState.url)
    console.log('Elements found:', pageState.elements.length)

    // Categorize elements
    const buttons = pageState.elements.filter(e => e.category === 'button')
    const inputs = pageState.elements.filter(e => e.category === 'text-input')
    const links = pageState.elements.filter(e => e.category === 'link')

    console.log('- Buttons:', buttons.length, buttons.slice(0, 3).map(b => b.text || b.label).join(', '))
    console.log('- Inputs:', inputs.length, inputs.slice(0, 3).map(i => i.label || i.placeholder || i.name).join(', '))
    console.log('- Links:', links.length)

    // Send element info to UI
    sendMessage?.('thinking', `📋 Found ${pageState.elements.length} elements (${buttons.length} buttons, ${inputs.length} inputs)`)

    // CHECK: Is this an exploration/analysis request? Handle autonomously!
    if (iteration === 1 && isExplorationRequest(userMessage)) {
      console.log('=== AUTONOMOUS EXPLORATION MODE ===')
      sendMessage?.('thinking', '🔍 Entering QA exploration mode...')

      const analysis = await analyzePageAutonomously(browserView, sendMessage)

      // Generate detailed QA report using AI
      const reportPrompt = `You are a senior QA engineer. You just analyzed a page. Give a DETAILED report.

PAGE ANALYSIS DATA:
${JSON.stringify(analysis, null, 2)}

Write a thorough QA report that includes:
1. **Page Overview** - What is this page? What's its purpose?
2. **Element Inventory** - What interactive elements did you find?
3. **Potential Issues** - Any problems you spotted (accessibility, usability, etc.)
4. **Test Recommendations** - What should be tested here?
5. **Security Considerations** - Any auth/form security concerns?

Be specific. Use the actual element names you found. Be curious and thorough like a real QA.
Don't ask questions - just report your findings. This is YOUR analysis.`

      try {
        const report = await callDeepSeek([
          { role: 'system', content: 'You are a senior QA engineer giving a detailed page analysis. Be thorough and specific.' },
          { role: 'user', content: reportPrompt }
        ], { maxTokens: 800, temperature: 0.3 })

        return {
          success: true,
          response: report.content,
          actionsTaken: 0,
          thinking: thinkingSteps.join('\n'),
          analysis
        }
      } catch (e) {
        // Fallback to basic report
        return {
          success: true,
          response: `**Page Analysis: ${analysis.title || analysis.url}**\n\n` +
            `Found ${analysis.elements.total} interactive elements:\n` +
            `- ${analysis.elements.buttons} buttons: ${analysis.keyButtons.join(', ')}\n` +
            `- ${analysis.elements.inputs} input fields\n` +
            `- ${analysis.elements.links} links\n\n` +
            (analysis.issues.length > 0 ? `**Issues Found:**\n${analysis.issues.join('\n')}` : 'No obvious issues detected.'),
          actionsTaken: 0,
          thinking: thinkingSteps.join('\n')
        }
      }
    }

    // Phase 3: Retrieve knowledge
    const pageType = detectPageType(pageState.url, pageState.elements)
    const knowledge = retrieveKnowledge(pageType, userMessage)
    thinkingSteps.push(`💭 ${ReasoningPhase.RETRIEVING}: Found ${knowledge.sections.length} knowledge sections for ${pageType}`)

    // Calculate confidence
    const confidence = calculateConfidence(pageState, knowledge, actionHistory)
    thinkingSteps.push(`💭 Confidence: ${confidence.level} (${Math.round(confidence.score * 100)}%)`)

    // Check if answer is already visible (for questions)
    const answerCheck = checkIfAnswered(userMessage, pageState)
    if (answerCheck.isQuestion && answerCheck.answered && iteration === 1) {
      const elements = answerCheck.matchingElements.slice(0, 5)
      thinkingSteps.push(`💭 Answer found on first look!`)
      return {
        success: true,
        response: `I can see what you're looking for!\n\n**Found on page:**\n${elements.map(e => `• ${e.text || e.label}`).join('\n')}`,
        actionsTaken: 0,
        thinking: thinkingSteps.join('\n'),
        confidence
      }
    }

    // Phase 4: Planning - Ask AI what to do
    thinkingSteps.push(`💭 ${ReasoningPhase.PLANNING}: Determining next action...`)

    const prompt = buildDecisionPrompt(
      userMessage,
      pageState,
      actionHistory,
      iteration,
      AGENT_LIMITS.maxIterations,
      knowledge
    )

    let decision
    try {
      console.log('=== ASKING AI FOR DECISION ===')
      console.log('Elements sent to AI:', pageState.elements.slice(0, 5).map(e => ({
        id: e.id,
        text: (e.text || e.label || '').slice(0, 30),
        category: e.category
      })))

      const response = await callDeepSeek([
        { role: 'system', content: BROWSER_AGENT_PERSONA + '\n\nReturn only valid JSON.' },
        { role: 'user', content: prompt }
      ], { jsonMode: true, maxTokens: 400, temperature: 0.1 })

      decision = JSON.parse(response.content)
      console.log('=== AI DECISION ===')
      console.log('Action:', decision.action)
      console.log('Element ID:', decision.elementId)
      console.log('Reason:', decision.reason)

      thinkingSteps.push(`💭 Decision: ${decision.action} ${decision.elementId || decision.url || ''}`)
      sendMessage?.('thinking', `🤔 Decided to: ${decision.action} ${decision.elementId ? `on ${decision.elementId}` : ''}`)
    } catch (e) {
      console.error('AI decision error:', e)
      decision = { action: 'cannot_proceed', reason: 'Failed to determine action: ' + e.message }
    }

    // Phase 5: Executing
    thinkingSteps.push(`💭 ${ReasoningPhase.EXECUTING}: ${decision.action}...`)

    const result = await executeAction(
      browserView,
      viewBounds,
      decision,
      pageState,
      userMessage,
      sendMessage
    )

    // Record in history
    actionHistory.push({
      action: decision.action,
      result: result.success ? result.message : `FAILED: ${result.message}`,
      elementId: decision.elementId
    })

    // Phase 6: Validating
    thinkingSteps.push(`💭 ${ReasoningPhase.VALIDATING}: ${result.success ? 'Success' : 'Failed'}`)

    // Check if we should stop
    if (shouldStopAfterAction(result)) {
      // ACTION COMPLETED - Now observe the result and respond naturally
      thinkingSteps.push(`💭 Action completed. Observing result...`)

      // Get fresh page state AFTER the action
      const newPageState = await getPageState(browserView)
      const newElements = formatElementsForAI(newPageState.elements, 20)

      // Ask AI to respond naturally based on what happened
      const responsePrompt = `You just completed an action for the user.

USER'S REQUEST: "${userMessage}"
ACTION TAKEN: ${result.message}

NEW PAGE STATE AFTER ACTION:
- URL: ${newPageState.url}
- Title: ${newPageState.title || 'Unknown'}
- Key elements visible: ${newElements.slice(0, 10).map(e => e.text).filter(Boolean).join(', ')}

Respond naturally to the user. Tell them:
1. What you did (briefly)
2. What you can see now (the result)
3. Offer to help with what's next

Be conversational, like a helpful human assistant. Keep it short (2-3 sentences).
Don't use technical IDs or JSON. Just talk naturally.`

      try {
        const naturalResponse = await callDeepSeek([
          { role: 'system', content: 'You are Alex, a friendly QA assistant. Respond naturally and conversationally.' },
          { role: 'user', content: responsePrompt }
        ], { maxTokens: 200, temperature: 0.5 })

        finalResponse = naturalResponse.content
      } catch (e) {
        // Fallback to basic message if AI fails
        finalResponse = result.message
      }

      break
    }

    // Wait for DOM to settle if changed
    if (result.domChanged) {
      await sleep(AGENT_LIMITS.domSettleTime)
    }

    // Check for repeated failures
    const recentFailures = actionHistory.slice(-3).filter(a => a.result.startsWith('FAILED'))
    if (recentFailures.length >= 3) {
      finalResponse = 'I seem to be stuck. Could you clarify what you need?'
      break
    }
  }

    // Summarize if we hit max iterations
    if (!finalResponse) {
      finalResponse = `Completed ${iteration} steps. ${actionHistory.filter(a => !a.result.startsWith('FAILED')).length} successful actions.`
    }

    return {
      success: true,
      response: finalResponse,
      actionsTaken: actionHistory.length,
      history: actionHistory,
      thinking: thinkingSteps.join('\n')
    }
  } catch (err) {
    console.error('Agent loop error:', err)
    return {
      success: false,
      error: `Agent error: ${err.message || String(err)}`,
      thinking: thinkingSteps.join('\n')
    }
  }
}

/**
 * Generate tests for current page (using QA_AGENT_PERSONA)
 */
async function generateTestsForPage(browserView, pageType) {
  const pageState = await getPageState(browserView)
  if (!pageState.hasPage) {
    return { success: false, error: 'No page loaded' }
  }

  const knowledge = retrieveKnowledge(pageType, 'generate tests')
  const elements = formatElementsForAI(pageState.elements, 50)

  const prompt = `${QA_AGENT_PERSONA}

Generate comprehensive test cases for this page.

PAGE INFO:
- URL: ${pageState.url}
- Title: ${pageState.title}
- Type: ${pageType}

ELEMENTS:
${JSON.stringify(elements, null, 2)}

${knowledge.formatted}

Generate 5-7 specific, actionable test cases. For each:
1. Test ID (TC_001, TC_002, etc.)
2. Name
3. Category (happy_path, edge_case, security, negative)
4. Priority (P0, P1, P2, P3)
5. Steps with specific test data
6. Expected result

Use REAL test data, not placeholders.

Return JSON:
{
  "testCases": [
    {
      "id": "TC_001",
      "name": "test name",
      "category": "category",
      "priority": "P0",
      "steps": [{ "action": "click/type/etc", "target": "element", "value": "data" }],
      "expectedResult": "what should happen"
    }
  ]
}`

  try {
    const response = await callDeepSeek([
      { role: 'system', content: 'Generate specific, actionable test cases. Return only valid JSON.' },
      { role: 'user', content: prompt }
    ], { jsonMode: true, maxTokens: 2000, temperature: 0.3 })

    const tests = JSON.parse(response.content)
    return {
      success: true,
      tests: tests.testCases || [],
      knowledge: knowledge.sections.map(s => s.title)
    }
  } catch (e) {
    return { success: false, error: e.message }
  }
}

/**
 * Analyze security for current page
 */
async function analyzeSecurityForPage(browserView, pageType) {
  const pageState = await getPageState(browserView)
  if (!pageState.hasPage) {
    return { success: false, error: 'No page loaded' }
  }

  const inputs = pageState.elements.filter(e => e.category === 'text-input')
  const hasAuthElements = inputs.some(e => e.type === 'password' || e.type === 'email')

  // Get security edge cases
  const edgeCases = {
    email: getEdgeCases('email'),
    password: getEdgeCases('password'),
    text: getEdgeCases('text')
  }

  const prompt = `You are a security-focused QA expert. Analyze this page for vulnerabilities.

PAGE INFO:
- URL: ${pageState.url}
- Type: ${pageType}
- Has auth elements: ${hasAuthElements}

INPUT FIELDS:
${inputs.map(e => `- ${e.label || e.name || e.id}: type=${e.type}`).join('\n')}

SECURITY TEST CASES TO TRY:
${JSON.stringify(edgeCases, null, 2)}

Identify:
1. Potential SQL injection points
2. XSS vulnerabilities
3. Authentication weaknesses
4. Input validation gaps

Return JSON:
{
  "vulnerabilities": [
    {
      "id": "VULN_001",
      "type": "xss|sql_injection|auth|validation",
      "severity": "critical|high|medium|low",
      "title": "vulnerability name",
      "description": "what's wrong",
      "testCase": "how to test it",
      "recommendation": "how to fix"
    }
  ]
}`

  try {
    const response = await callDeepSeek([
      { role: 'system', content: 'Identify security vulnerabilities. Return only valid JSON.' },
      { role: 'user', content: prompt }
    ], { jsonMode: true, maxTokens: 1500, temperature: 0.2 })

    const analysis = JSON.parse(response.content)
    return {
      success: true,
      vulnerabilities: analysis.vulnerabilities || [],
      hasAuthElements
    }
  } catch (e) {
    return { success: false, error: e.message }
  }
}

/**
 * Quick answer check - for simple questions
 */
async function quickAnswerCheck(browserView, userMessage) {
  const pageState = await getPageState(browserView)
  if (!pageState.hasPage) return null

  const check = checkIfAnswered(userMessage, pageState)
  if (check.isQuestion && check.answered) {
    return {
      found: true,
      elements: check.matchingElements.slice(0, 5)
    }
  }

  return null
}

module.exports = {
  runAgentLoop,
  generateTestsForPage,
  analyzeSecurityForPage,
  quickAnswerCheck,
  checkIfAnswered,
  ReasoningPhase
}
