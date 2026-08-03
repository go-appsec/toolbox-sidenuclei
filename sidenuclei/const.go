package main

// Log levels, kept as constants so repeated literals stay below goconst's threshold.
const (
	logInfo  = "info"
	logWarn  = "warn"
	logError = "error"
)

// Structured log field keys.
const (
	flowIDField = "flow_id"
	targetField = "target"
	errField    = "err"
)
