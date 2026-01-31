"""
TestAI Agent - Logging System

Provides structured logging for:
- Debug information
- API calls and responses
- Knowledge retrieval
- Test plan generation
- Error tracking

Logs are stored in .logs/ directory.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import json


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for easier parsing."""
    
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        if hasattr(record, 'extra'):
            log_obj["extra"] = record.extra
            
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_obj)


class ConsoleFormatter(logging.Formatter):
    """Human-readable console formatting with colors."""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m',
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        return f"{color}[{timestamp}] {record.levelname:8}{reset} | {record.getMessage()}"


def setup_logging(
    name: str = "testai",
    level: int = logging.INFO,
    log_dir: str = ".logs",
    console: bool = True,
    file: bool = True,
    json_format: bool = False
) -> logging.Logger:
    """
    Set up logging for the TestAI Agent.
    
    Args:
        name: Logger name
        level: Logging level
        log_dir: Directory for log files
        console: Enable console output
        file: Enable file output
        json_format: Use JSON format for file logs
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(level)
        console_handler.setFormatter(ConsoleFormatter())
        logger.addHandler(console_handler)
    
    # File handler
    if file:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        
        date_str = datetime.now().strftime('%Y%m%d')
        log_file = log_path / f"testai_{date_str}.log"
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        
        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s'
            ))
            
        logger.addHandler(file_handler)
        
    return logger


class LogContext:
    """
    Context manager for structured logging.
    
    Usage:
        with LogContext(logger, "Generating test plan", feature="login"):
            # ... do work
            pass
    """
    
    def __init__(self, logger: logging.Logger, message: str, **kwargs):
        self.logger = logger
        self.message = message
        self.kwargs = kwargs
        self.start_time = None
        
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.info(f"START: {self.message}", extra=self.kwargs)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type:
            self.logger.error(
                f"FAILED: {self.message} after {duration:.2f}s - {exc_val}",
                extra={**self.kwargs, "duration": duration, "error": str(exc_val)}
            )
        else:
            self.logger.info(
                f"COMPLETE: {self.message} in {duration:.2f}s",
                extra={**self.kwargs, "duration": duration}
            )
            
        return False  # Don't suppress exceptions


# Module-level logger
_logger: Optional[logging.Logger] = None


def get_logger() -> logging.Logger:
    """Get the global logger instance."""
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger


def log_api_call(provider: str, model: str, tokens: int, cost: float, latency: float):
    """Log an API call."""
    logger = get_logger()
    logger.info(
        f"API CALL: {provider}/{model} - {tokens} tokens, ${cost:.4f}, {latency:.0f}ms"
    )


def log_knowledge_retrieval(query: str, results: int, confidence: float):
    """Log a knowledge retrieval operation."""
    logger = get_logger()
    logger.info(
        f"RETRIEVAL: '{query[:50]}...' - {results} results, {confidence:.0%} confidence"
    )


def log_test_generation(feature: str, test_count: int, risk: str):
    """Log test plan generation."""
    logger = get_logger()
    logger.info(
        f"GENERATED: {feature} - {test_count} tests, {risk} risk"
    )
