package logging

import (
	"fmt"
	"log"
)

// Logger provides a consistent logging interface with debug support
type Logger struct {
	debug  bool
	prefix string
}

// NewLogger creates a new logger instance
func NewLogger(debug bool, prefix string) *Logger {
	return &Logger{
		debug:  debug,
		prefix: prefix,
	}
}

// Debug logs a message only when debug mode is enabled
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.debug {
		log.Printf("Debug: "+format, args...)
	}
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	log.Printf("Warning: "+format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	log.Printf("ERROR: "+format, args...)
}

// Fatal logs an error message and exits the program
func (l *Logger) Fatal(format string, args ...interface{}) {
	log.Fatalf("FATAL: "+format, args...)
}

// Console prints a message to stdout (for user-facing output)
func (l *Logger) Console(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// SetDebug enables or disables debug logging
func (l *Logger) SetDebug(debug bool) {
	l.debug = debug
}

// IsDebug returns whether debug logging is enabled
func (l *Logger) IsDebug() bool {
	return l.debug
}
