package client

import "log"

type logWrapper struct {
	logger *log.Logger
	debug  bool
}

func newLogWrapper(logger *log.Logger) *logWrapper {
	return &logWrapper{logger: logger}
}

func (l *logWrapper) setDebug(enabled bool) {
	l.debug = enabled
}

func (l *logWrapper) Infof(format string, args ...interface{}) {
	l.logger.Printf("INFO: "+format, args...)
}

func (l *logWrapper) Warnf(format string, args ...interface{}) {
	l.logger.Printf("WARN: "+format, args...)
}

func (l *logWrapper) Errorf(format string, args ...interface{}) {
	l.logger.Printf("ERROR: "+format, args...)
}

func (l *logWrapper) Debugf(format string, args ...interface{}) {
	if l.debug {
		l.logger.Printf("DEBUG: "+format, args...)
	}
}
