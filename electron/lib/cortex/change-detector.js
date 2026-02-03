/**
 * Yali Agent - Change Detector
 * Ported from testai-agent/impact/change_detector.py
 *
 * Detects and categorizes code changes from git diffs
 * or file comparisons for impact analysis.
 */

/**
 * Types of code changes
 */
const ChangeType = {
  ADDED: 'added',
  MODIFIED: 'modified',
  DELETED: 'deleted',
  RENAMED: 'renamed',
  MOVED: 'moved'
}

/**
 * Create a code change object
 */
function createCodeChange(filePath, changeType, options = {}) {
  return {
    filePath,
    changeType,
    oldPath: options.oldPath || null, // For renames
    addedLines: options.addedLines || 0,
    deletedLines: options.deletedLines || 0,
    modifiedFunctions: options.modifiedFunctions || [],
    modifiedClasses: options.modifiedClasses || [],
    affectedImports: options.affectedImports || [],
    isTestFile: options.isTestFile || false,
    contentPreview: options.contentPreview || ''
  }
}

/**
 * Create a change set (e.g., from a commit)
 */
function createChangeSet(id, description, changes, options = {}) {
  return {
    id,
    description,
    changes,
    timestamp: options.timestamp || new Date(),
    author: options.author || '',
    totalAdditions: changes.reduce((sum, c) => sum + c.addedLines, 0),
    totalDeletions: changes.reduce((sum, c) => sum + c.deletedLines, 0),
    filesChanged: changes.length,
    metadata: options.metadata || {}
  }
}

/**
 * Change Detector class
 */
class ChangeDetector {
  // Patterns for extracting code elements
  static FUNCTION_PATTERNS = {
    python: /^\+?\s*def\s+(\w+)\s*\(/gm,
    javascript: /^\+?\s*(function\s+(\w+)|(\w+)\s*=\s*(async\s+)?function|\b(\w+)\s*\([^)]*\)\s*{)/gm,
    typescript: /^\+?\s*(function\s+(\w+)|(\w+)\s*=\s*(async\s+)?function|\b(\w+)\s*\([^)]*\)\s*:)/gm
  }

  static CLASS_PATTERNS = {
    python: /^\+?\s*class\s+(\w+)/gm,
    javascript: /^\+?\s*class\s+(\w+)/gm,
    typescript: /^\+?\s*class\s+(\w+)/gm
  }

  static IMPORT_PATTERNS = {
    python: /^\+?\s*(from\s+[\w.]+\s+import|import\s+[\w.]+)/gm,
    javascript: /^\+?\s*(import\s+.*from|require\s*\()/gm,
    typescript: /^\+?\s*(import\s+.*from|require\s*\()/gm
  }

  static TEST_FILE_PATTERNS = [
    /test_.*\.py$/,
    /.*_test\.py$/,
    /.*\.test\.(js|ts|jsx|tsx)$/,
    /.*\.spec\.(js|ts|jsx|tsx)$/,
    /tests?\/.*\.(py|js|ts)$/,
    /__tests__\/.*\.(js|ts|jsx|tsx)$/
  ]

  constructor() {
    // Pre-compile test patterns
    this._testPatterns = ChangeDetector.TEST_FILE_PATTERNS
  }

  /**
   * Parse a git diff into a ChangeSet
   */
  parseGitDiff(diffContent, changeId = '', description = '') {
    const changes = []
    let currentFile = null
    let currentChangeType = null
    let oldPath = null
    let addedLines = 0
    let deletedLines = 0
    let diffContentBuffer = []

    for (const line of diffContent.split('\n')) {
      // New file marker
      if (line.startsWith('diff --git')) {
        // Save previous file if exists
        if (currentFile) {
          changes.push(this._createChange(
            currentFile,
            currentChangeType,
            oldPath,
            addedLines,
            deletedLines,
            diffContentBuffer.join('\n')
          ))
        }

        // Reset for new file
        const parts = line.split(' ')
        if (parts.length >= 4) {
          currentFile = parts[3].slice(2) // Remove b/ prefix
          oldPath = parts[2].slice(2)      // Remove a/ prefix
        }
        currentChangeType = ChangeType.MODIFIED
        addedLines = 0
        deletedLines = 0
        diffContentBuffer = []
      }

      // New file indicator
      else if (line.startsWith('new file')) {
        currentChangeType = ChangeType.ADDED
      }

      // Deleted file indicator
      else if (line.startsWith('deleted file')) {
        currentChangeType = ChangeType.DELETED
      }

      // Renamed file indicator
      else if (line.startsWith('rename from')) {
        currentChangeType = ChangeType.RENAMED
        oldPath = line.replace('rename from ', '')
      }

      else if (line.startsWith('rename to') && currentChangeType === ChangeType.RENAMED) {
        currentFile = line.replace('rename to ', '')
      }

      // Count additions and deletions
      else if (line.startsWith('+') && !line.startsWith('+++')) {
        addedLines++
        diffContentBuffer.push(line)
      }

      else if (line.startsWith('-') && !line.startsWith('---')) {
        deletedLines++
        diffContentBuffer.push(line)
      }
    }

    // Save last file
    if (currentFile) {
      changes.push(this._createChange(
        currentFile,
        currentChangeType,
        oldPath,
        addedLines,
        deletedLines,
        diffContentBuffer.join('\n')
      ))
    }

    return createChangeSet(
      changeId || `CS-${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}`,
      description,
      changes
    )
  }

  /**
   * Create a ChangeSet from a list of file changes
   */
  parseFileList(files, changeId = '', description = '') {
    const changes = files.map(fileInfo => createCodeChange(
      fileInfo.path || '',
      fileInfo.type || ChangeType.MODIFIED,
      {
        oldPath: fileInfo.oldPath,
        addedLines: fileInfo.added || 0,
        deletedLines: fileInfo.deleted || 0,
        modifiedFunctions: fileInfo.functions || [],
        modifiedClasses: fileInfo.classes || [],
        isTestFile: this._isTestFile(fileInfo.path || '')
      }
    ))

    return createChangeSet(
      changeId || `CS-${new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)}`,
      description,
      changes
    )
  }

  /**
   * Extract modified functions and classes from diff
   */
  extractModifiedElements(diffContent, language = 'python') {
    const results = {
      functions: [],
      classes: [],
      imports: []
    }

    const funcPattern = ChangeDetector.FUNCTION_PATTERNS[language]
    const classPattern = ChangeDetector.CLASS_PATTERNS[language]
    const importPattern = ChangeDetector.IMPORT_PATTERNS[language]

    if (funcPattern) {
      const regex = new RegExp(funcPattern.source, funcPattern.flags)
      let match
      while ((match = regex.exec(diffContent)) !== null) {
        // Get first non-empty capture group
        const name = match.slice(1).find(m => m)
        if (name && !results.functions.includes(name)) {
          results.functions.push(name)
        }
      }
    }

    if (classPattern) {
      const regex = new RegExp(classPattern.source, classPattern.flags)
      let match
      while ((match = regex.exec(diffContent)) !== null) {
        if (match[1] && !results.classes.includes(match[1])) {
          results.classes.push(match[1])
        }
      }
    }

    if (importPattern) {
      const regex = new RegExp(importPattern.source, importPattern.flags)
      let match
      while ((match = regex.exec(diffContent)) !== null) {
        if (match[1] && !results.imports.includes(match[1])) {
          results.imports.push(match[1])
        }
      }
    }

    return results
  }

  /**
   * Categorize changes by type
   */
  categorizeChanges(changeset) {
    const categories = {
      sourceCode: [],
      testCode: [],
      configuration: [],
      documentation: [],
      other: []
    }

    const configExtensions = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg'])
    const docExtensions = new Set(['.md', '.rst', '.txt', '.adoc'])
    const codeExtensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go']

    for (const change of changeset.changes) {
      const path = change.filePath.toLowerCase()

      if (change.isTestFile) {
        categories.testCode.push(change)
      } else if ([...configExtensions].some(ext => path.endsWith(ext))) {
        categories.configuration.push(change)
      } else if ([...docExtensions].some(ext => path.endsWith(ext))) {
        categories.documentation.push(change)
      } else if (codeExtensions.some(ext => path.endsWith(ext))) {
        categories.sourceCode.push(change)
      } else {
        categories.other.push(change)
      }
    }

    return categories
  }

  /**
   * Get the set of affected modules/packages
   */
  getAffectedModules(changeset) {
    const modules = new Set()

    for (const change of changeset.changes) {
      const parts = change.filePath.split('/')
      // Get top-level directory as module
      if (parts.length > 1) {
        modules.add(parts[0])
      }
      // Also add parent directories for deeper files
      for (let i = 0; i < parts.length - 1; i++) {
        modules.add(parts.slice(0, i + 1).join('/'))
      }
    }

    return modules
  }

  /**
   * Calculate risk score for a change (0-1)
   */
  calculateChangeRisk(change) {
    let risk = 0.0

    // More lines changed = higher risk
    const totalLines = change.addedLines + change.deletedLines
    if (totalLines > 100) {
      risk += 0.3
    } else if (totalLines > 50) {
      risk += 0.2
    } else if (totalLines > 10) {
      risk += 0.1
    }

    // Function/class modifications = higher risk
    if (change.modifiedFunctions.length > 0) {
      risk += 0.2 * Math.min(change.modifiedFunctions.length / 5, 1.0)
    }
    if (change.modifiedClasses.length > 0) {
      risk += 0.2 * Math.min(change.modifiedClasses.length / 3, 1.0)
    }

    // Deletions are riskier than additions
    if (change.deletedLines > change.addedLines) {
      risk += 0.1
    }

    // Test file changes have lower risk (for production)
    if (change.isTestFile) {
      risk *= 0.5
    }

    return Math.min(risk, 1.0)
  }

  _createChange(filePath, changeType, oldPath, addedLines, deletedLines, diffContent) {
    const language = this._detectLanguage(filePath)
    const elements = this.extractModifiedElements(diffContent, language)

    return createCodeChange(filePath, changeType || ChangeType.MODIFIED, {
      oldPath: oldPath !== filePath ? oldPath : null,
      addedLines,
      deletedLines,
      modifiedFunctions: elements.functions,
      modifiedClasses: elements.classes,
      affectedImports: elements.imports,
      isTestFile: this._isTestFile(filePath),
      contentPreview: diffContent.slice(0, 500)
    })
  }

  _isTestFile(filePath) {
    return this._testPatterns.some(pattern => pattern.test(filePath))
  }

  _detectLanguage(filePath) {
    const extensionMap = {
      '.py': 'python',
      '.js': 'javascript',
      '.jsx': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'typescript'
    }

    for (const [ext, lang] of Object.entries(extensionMap)) {
      if (filePath.endsWith(ext)) {
        return lang
      }
    }

    return 'python' // Default
  }

  /**
   * Format a ChangeSet as readable text
   */
  formatChangeset(changeset) {
    const lines = [
      '='.repeat(60),
      `  CHANGESET: ${changeset.id}`,
      '='.repeat(60),
      '',
      `  Description: ${changeset.description}`,
      `  Timestamp: ${changeset.timestamp.toISOString().slice(0, 16).replace('T', ' ')}`,
      `  Author: ${changeset.author || 'Unknown'}`,
      '',
      `  Files Changed: ${changeset.filesChanged}`,
      `  Lines Added: +${changeset.totalAdditions}`,
      `  Lines Deleted: -${changeset.totalDeletions}`,
      '',
      '-'.repeat(60),
      '  CHANGES',
      '-'.repeat(60)
    ]

    const typeIcons = {
      [ChangeType.ADDED]: '+',
      [ChangeType.MODIFIED]: 'M',
      [ChangeType.DELETED]: '-',
      [ChangeType.RENAMED]: 'R',
      [ChangeType.MOVED]: '>'
    }

    for (const change of changeset.changes) {
      const icon = typeIcons[change.changeType] || '*'
      const risk = this.calculateChangeRisk(change)
      const riskIndicator = risk > 0.6 ? '[HIGH]' : risk > 0.3 ? '[MED]' : '[LOW]'

      lines.push(`\n  ${icon} ${change.filePath} ${riskIndicator}`)
      lines.push(`     +${change.addedLines} -${change.deletedLines}`)

      if (change.modifiedFunctions.length > 0) {
        let funcs = change.modifiedFunctions.slice(0, 5).join(', ')
        if (change.modifiedFunctions.length > 5) {
          funcs += ` (+${change.modifiedFunctions.length - 5} more)`
        }
        lines.push(`     Functions: ${funcs}`)
      }

      if (change.modifiedClasses.length > 0) {
        const classes = change.modifiedClasses.slice(0, 3).join(', ')
        lines.push(`     Classes: ${classes}`)
      }
    }

    lines.push('')
    lines.push('='.repeat(60))
    return lines.join('\n')
  }

  /**
   * Get high-risk changes that need extra testing
   */
  getHighRiskChanges(changeset, threshold = 0.5) {
    return changeset.changes.filter(c => this.calculateChangeRisk(c) >= threshold)
  }

  /**
   * Get summary for test prioritization
   */
  getSummaryForTesting(changeset) {
    const categories = this.categorizeChanges(changeset)
    const highRisk = this.getHighRiskChanges(changeset)
    const modules = this.getAffectedModules(changeset)

    return {
      totalChanges: changeset.changes.length,
      sourceCodeChanges: categories.sourceCode.length,
      testCodeChanges: categories.testCode.length,
      highRiskChanges: highRisk.length,
      affectedModules: [...modules],
      allModifiedFunctions: [...new Set(changeset.changes.flatMap(c => c.modifiedFunctions))],
      allModifiedClasses: [...new Set(changeset.changes.flatMap(c => c.modifiedClasses))],
      recommendation: this._getTestingRecommendation(changeset, highRisk)
    }
  }

  _getTestingRecommendation(changeset, highRisk) {
    if (highRisk.length === 0) {
      return 'Low risk changes - standard regression testing sufficient'
    }
    if (highRisk.length > 5) {
      return 'High risk - run full test suite with focus on affected modules'
    }
    if (highRisk.some(c => c.modifiedClasses.length > 0)) {
      return 'Class modifications detected - prioritize integration tests'
    }
    return 'Moderate risk - run targeted tests on modified functions'
  }
}

/**
 * Helper to create a change detector
 */
function createChangeDetector() {
  return new ChangeDetector()
}

module.exports = {
  // Enums
  ChangeType,

  // Factory functions
  createCodeChange,
  createChangeSet,

  // Main class
  ChangeDetector,
  createChangeDetector
}
