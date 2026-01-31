/**
 * TestAI Agent - Main Entry Point
 *
 * Exports all agent components for integration with Electron app.
 */

export * from './types'
export { DeepSeekClient, createDeepSeekClient } from './deepseek-client'
export { ScriptGenerator, createScriptGenerator } from './script-generator'
export { AutonomousTester, createAutonomousTester } from './autonomous-tester'
