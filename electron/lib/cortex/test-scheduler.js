/**
 * Yali Agent - Test Scheduler
 * Ported from testai-agent/orchestrator/scheduler.py
 *
 * Schedules test execution across browsers, devices,
 * and time windows with intelligent prioritization.
 */

/**
 * Types of schedules
 */
const ScheduleType = {
  IMMEDIATE: 'immediate',
  SCHEDULED: 'scheduled',
  RECURRING: 'recurring',
  ON_DEMAND: 'on_demand'
}

/**
 * Schedule status
 */
const ScheduleStatus = {
  PENDING: 'pending',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CANCELLED: 'cancelled',
  PAUSED: 'paused'
}

/**
 * Recurrence patterns
 */
const RecurrencePattern = {
  HOURLY: 'hourly',
  DAILY: 'daily',
  WEEKLY: 'weekly',
  MONTHLY: 'monthly',
  CUSTOM: 'custom'
}

/**
 * Default browser targets
 */
const DEFAULT_BROWSERS = [
  { browser: 'chromium', headless: true },
  { browser: 'firefox', headless: true },
  { browser: 'webkit', headless: true }
]

/**
 * Default device targets
 */
const DEFAULT_DEVICES = [
  { name: 'Desktop HD', width: 1920, height: 1080, deviceScaleFactor: 1.0, isMobile: false, hasTouch: false },
  { name: 'Desktop', width: 1366, height: 768, deviceScaleFactor: 1.0, isMobile: false, hasTouch: false },
  { name: 'Tablet', width: 768, height: 1024, deviceScaleFactor: 1.0, isMobile: false, hasTouch: true },
  { name: 'Mobile', width: 375, height: 667, deviceScaleFactor: 2.0, isMobile: true, hasTouch: true }
]

/**
 * Create a browser target
 */
function createBrowserTarget(browser, version = null, headless = true) {
  return { browser, version, headless }
}

/**
 * Create a device target
 */
function createDeviceTarget(name, width, height, options = {}) {
  return {
    name,
    width,
    height,
    deviceScaleFactor: options.deviceScaleFactor || 1.0,
    isMobile: options.isMobile || false,
    hasTouch: options.hasTouch || false,
    userAgent: options.userAgent || null
  }
}

/**
 * Create a schedule config
 */
function createScheduleConfig(options = {}) {
  return {
    maxParallelRuns: options.maxParallelRuns || 5,
    defaultTimeoutMinutes: options.defaultTimeoutMinutes || 60,
    retryFailed: options.retryFailed !== false,
    maxRetries: options.maxRetries || 2,
    queueTimeoutMinutes: options.queueTimeoutMinutes || 120,
    priorityBoostOnFailure: options.priorityBoostOnFailure !== false
  }
}

/**
 * Create a scheduled run
 */
function createScheduledRun(runId, testIds, options = {}) {
  return {
    runId,
    testIds,
    browsers: options.browsers || [createBrowserTarget('chromium')],
    devices: options.devices || [createDeviceTarget('Desktop', 1366, 768)],
    scheduleType: options.scheduleType || ScheduleType.IMMEDIATE,
    scheduledTime: options.scheduledTime || new Date(),
    status: ScheduleStatus.PENDING,
    priority: options.priority || 5, // Lower = higher priority
    tags: options.tags || [],
    environment: options.environment || 'default',
    timeoutMinutes: options.timeoutMinutes || 60,
    retryCount: options.retryCount || 0,
    createdAt: new Date(),
    startedAt: null,
    completedAt: null,
    result: null,
    metadata: options.metadata || {}
  }
}

/**
 * Test Scheduler class - Priority-based scheduling across browsers/devices
 */
class TestScheduler {
  constructor(config = null) {
    this.config = config || createScheduleConfig()
    this._runCounter = 0
    this._queue = [] // Priority queue (array sorted by priority/time)
    this._running = new Map()
    this._completed = new Map()
    this._recurring = new Map()
    this._hooks = {
      onScheduled: [],
      onStarted: [],
      onCompleted: [],
      onFailed: []
    }
  }

  /**
   * Schedule a test run
   */
  schedule(testIds, options = {}) {
    this._runCounter++
    const runId = `sched-${String(this._runCounter).padStart(5, '0')}-${this._randomHex(8)}`

    const scheduleType = options.scheduleTime ? ScheduleType.SCHEDULED : ScheduleType.IMMEDIATE
    const scheduledTime = options.scheduleTime || new Date()

    const run = createScheduledRun(runId, testIds, {
      browsers: options.browsers || [createBrowserTarget('chromium')],
      devices: options.devices || [createDeviceTarget('Desktop', 1366, 768)],
      scheduleType,
      scheduledTime,
      priority: options.priority || 5,
      tags: options.tags || [],
      environment: options.environment || 'default',
      timeoutMinutes: options.timeoutMinutes || this.config.defaultTimeoutMinutes
    })

    this._insertQueue(run)
    this._runHooks('onScheduled', run)

    return run
  }

  /**
   * Schedule tests across a browser/device matrix
   */
  scheduleMatrix(testIds, options = {}) {
    const browsers = options.browsers || DEFAULT_BROWSERS
    const devices = options.devices || DEFAULT_DEVICES

    const runs = []
    for (const browser of browsers) {
      for (const device of devices) {
        const run = this.schedule(testIds, {
          browsers: [browser],
          devices: [device],
          priority: options.priority || 5,
          environment: options.environment || 'default',
          tags: [browser.browser, device.name.toLowerCase().replace(/ /g, '_')]
        })
        runs.push(run)
      }
    }

    return runs
  }

  /**
   * Schedule a recurring test run
   */
  scheduleRecurring(testIds, pattern, options = {}) {
    this._runCounter++
    const runId = `recur-${String(this._runCounter).padStart(5, '0')}-${this._randomHex(8)}`

    const startTime = options.startTime || new Date()

    const run = createScheduledRun(runId, testIds, {
      browsers: options.browsers || [createBrowserTarget('chromium')],
      devices: [createDeviceTarget('Desktop', 1366, 768)],
      scheduleType: ScheduleType.RECURRING,
      scheduledTime: startTime,
      priority: options.priority || 5,
      tags: ['recurring', pattern],
      environment: 'default',
      metadata: {
        pattern,
        customIntervalMinutes: options.customIntervalMinutes
      }
    })

    this._recurring.set(runId, run)
    this._insertQueue(run)

    return run
  }

  /**
   * Get the next scheduled run to execute
   */
  getNext() {
    while (this._queue.length > 0) {
      // Check if we can run more
      if (this._running.size >= this.config.maxParallelRuns) {
        return null
      }

      const run = this._queue.shift()

      // Check if it's time
      if (run.scheduledTime > new Date()) {
        this._insertQueue(run)
        return null
      }

      // Check if cancelled
      if (run.status === ScheduleStatus.CANCELLED) {
        continue
      }

      return run
    }

    return null
  }

  /**
   * Mark a run as started
   */
  startRun(runId) {
    const run = this._findRun(runId)
    if (!run) return false

    run.status = ScheduleStatus.RUNNING
    run.startedAt = new Date()
    this._running.set(runId, run)

    this._runHooks('onStarted', run)
    return true
  }

  /**
   * Mark a run as completed
   */
  completeRun(runId, result, success = true) {
    const run = this._running.get(runId)
    if (!run) return false

    this._running.delete(runId)

    run.status = success ? ScheduleStatus.COMPLETED : ScheduleStatus.FAILED
    run.completedAt = new Date()
    run.result = result

    this._completed.set(runId, run)

    // Handle failure with retry
    if (!success && this.config.retryFailed) {
      if (run.retryCount < this.config.maxRetries) {
        this._scheduleRetry(run)
      }
    }

    // Schedule next occurrence for recurring
    if (run.scheduleType === ScheduleType.RECURRING) {
      this._scheduleNextOccurrence(run)
    }

    const hook = success ? 'onCompleted' : 'onFailed'
    this._runHooks(hook, run)

    return true
  }

  _scheduleRetry(run) {
    this._runCounter++
    const retryId = `retry-${String(this._runCounter).padStart(5, '0')}-${this._randomHex(8)}`

    // Boost priority for retries
    let newPriority = run.priority
    if (this.config.priorityBoostOnFailure) {
      newPriority = Math.max(1, run.priority - 1)
    }

    const retry = createScheduledRun(retryId, run.testIds, {
      browsers: run.browsers,
      devices: run.devices,
      scheduleType: ScheduleType.IMMEDIATE,
      scheduledTime: new Date(Date.now() + 60000), // 1 minute delay
      priority: newPriority,
      tags: [...run.tags, 'retry'],
      environment: run.environment,
      timeoutMinutes: run.timeoutMinutes,
      retryCount: run.retryCount + 1,
      metadata: { originalRun: run.runId }
    })

    this._insertQueue(retry)
  }

  _scheduleNextOccurrence(run) {
    const pattern = run.metadata.pattern || 'daily'
    const customInterval = run.metadata.customIntervalMinutes

    // Calculate next time
    let nextTime
    const prevTime = run.scheduledTime.getTime()

    switch (pattern) {
      case RecurrencePattern.HOURLY:
        nextTime = new Date(prevTime + 60 * 60 * 1000)
        break
      case RecurrencePattern.DAILY:
        nextTime = new Date(prevTime + 24 * 60 * 60 * 1000)
        break
      case RecurrencePattern.WEEKLY:
        nextTime = new Date(prevTime + 7 * 24 * 60 * 60 * 1000)
        break
      case RecurrencePattern.MONTHLY:
        nextTime = new Date(prevTime + 30 * 24 * 60 * 60 * 1000)
        break
      case RecurrencePattern.CUSTOM:
        if (customInterval) {
          nextTime = new Date(prevTime + customInterval * 60 * 1000)
        } else {
          nextTime = new Date(prevTime + 24 * 60 * 60 * 1000)
        }
        break
      default:
        nextTime = new Date(prevTime + 24 * 60 * 60 * 1000)
    }

    // Create new occurrence
    this._runCounter++
    const newId = `recur-${String(this._runCounter).padStart(5, '0')}-${this._randomHex(8)}`

    const newRun = createScheduledRun(newId, run.testIds, {
      browsers: run.browsers,
      devices: run.devices,
      scheduleType: ScheduleType.RECURRING,
      scheduledTime: nextTime,
      priority: run.priority,
      tags: run.tags,
      environment: run.environment,
      timeoutMinutes: run.timeoutMinutes,
      metadata: run.metadata
    })

    this._recurring.set(newId, newRun)
    this._insertQueue(newRun)
  }

  /**
   * Cancel a scheduled run
   */
  cancelRun(runId) {
    const run = this._findRun(runId)
    if (!run) return false

    if (run.status === ScheduleStatus.RUNNING) return false

    run.status = ScheduleStatus.CANCELLED
    return true
  }

  /**
   * Pause a scheduled run
   */
  pauseRun(runId) {
    const run = this._findRun(runId)
    if (!run) return false

    if (run.status !== ScheduleStatus.PENDING) return false

    run.status = ScheduleStatus.PAUSED
    return true
  }

  /**
   * Resume a paused run
   */
  resumeRun(runId) {
    const run = this._findRun(runId)
    if (!run) return false

    if (run.status !== ScheduleStatus.PAUSED) return false

    run.status = ScheduleStatus.PENDING
    return true
  }

  _findRun(runId) {
    // Check queue
    const inQueue = this._queue.find(r => r.runId === runId)
    if (inQueue) return inQueue

    // Check running
    if (this._running.has(runId)) return this._running.get(runId)

    // Check completed
    if (this._completed.has(runId)) return this._completed.get(runId)

    return null
  }

  /**
   * Get a run by ID
   */
  getRun(runId) {
    return this._findRun(runId)
  }

  /**
   * Get all pending runs
   */
  getPending() {
    return this._queue.filter(r => r.status === ScheduleStatus.PENDING)
  }

  /**
   * Get all running runs
   */
  getRunning() {
    return Array.from(this._running.values())
  }

  /**
   * Get recent completed runs
   */
  getCompleted(limit = 10) {
    const completed = Array.from(this._completed.values())
    completed.sort((a, b) => (b.completedAt || 0) - (a.completedAt || 0))
    return completed.slice(0, limit)
  }

  /**
   * Add a hook for an event
   */
  addHook(event, callback) {
    if (this._hooks[event]) {
      this._hooks[event].push(callback)
    }
  }

  _runHooks(event, run) {
    for (const callback of this._hooks[event] || []) {
      try {
        callback(run)
      } catch (e) {
        // Ignore hook errors
      }
    }
  }

  _insertQueue(run) {
    // Insert maintaining priority order (lower priority number = higher priority)
    const idx = this._queue.findIndex(r => {
      if (r.priority !== run.priority) {
        return r.priority > run.priority
      }
      return r.scheduledTime > run.scheduledTime
    })

    if (idx === -1) {
      this._queue.push(run)
    } else {
      this._queue.splice(idx, 0, run)
    }
  }

  _randomHex(length) {
    return [...Array(length)].map(() => Math.floor(Math.random() * 16).toString(16)).join('')
  }

  /**
   * Get scheduler statistics
   */
  getStatistics() {
    const pending = this._queue.filter(r => r.status === ScheduleStatus.PENDING).length
    const running = this._running.size
    const completed = Array.from(this._completed.values()).filter(r => r.status === ScheduleStatus.COMPLETED).length
    const failed = Array.from(this._completed.values()).filter(r => r.status === ScheduleStatus.FAILED).length

    return {
      pendingRuns: pending,
      runningRuns: running,
      completedRuns: completed,
      failedRuns: failed,
      recurringSchedules: this._recurring.size,
      maxParallel: this.config.maxParallelRuns,
      capacityUsed: this.config.maxParallelRuns > 0 ? running / this.config.maxParallelRuns : 0
    }
  }

  /**
   * Format scheduler status
   */
  formatStatus() {
    const stats = this.getStatistics()

    const lines = [
      '='.repeat(60),
      '  TEST SCHEDULER STATUS',
      '='.repeat(60),
      '',
      `  Pending: ${stats.pendingRuns}`,
      `  Running: ${stats.runningRuns}/${stats.maxParallel}`,
      `  Completed: ${stats.completedRuns}`,
      `  Failed: ${stats.failedRuns}`,
      `  Recurring: ${stats.recurringSchedules}`,
      ''
    ]

    if (this._running.size > 0) {
      lines.push('-'.repeat(60))
      lines.push('  RUNNING')
      lines.push('-'.repeat(60))
      for (const run of this._running.values()) {
        const duration = run.startedAt ? Math.floor((Date.now() - run.startedAt.getTime()) / 1000) : 0
        lines.push(`  \u{1F504} ${run.runId} - ${run.testIds.length} tests (${duration}s)`)
      }
    }

    const pending = this._queue.filter(r => r.status === ScheduleStatus.PENDING).slice(0, 5)
    if (pending.length > 0) {
      lines.push('')
      lines.push('-'.repeat(60))
      lines.push('  PENDING')
      lines.push('-'.repeat(60))
      for (const run of pending) {
        const timeStr = run.scheduledTime.toTimeString().slice(0, 8)
        lines.push(`  \u{23F3} ${run.runId} - scheduled ${timeStr}`)
      }
    }

    lines.push('')
    lines.push('='.repeat(60))
    return lines.join('\n')
  }
}

/**
 * Helper to create a scheduler
 */
function createTestScheduler(config = null) {
  return new TestScheduler(config)
}

module.exports = {
  // Enums
  ScheduleType,
  ScheduleStatus,
  RecurrencePattern,

  // Defaults
  DEFAULT_BROWSERS,
  DEFAULT_DEVICES,

  // Factory functions
  createBrowserTarget,
  createDeviceTarget,
  createScheduleConfig,
  createScheduledRun,

  // Main class
  TestScheduler,
  createTestScheduler
}
