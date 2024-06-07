package main

import (
	"ibm/container_cryptography_scanner/cmd"
	"log/slog"
	"os"
)

// Function used to set logging and start cobra
func main() {
	logHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: false,
	})
	logger := slog.New(logHandler)
	logger.Handler().WithAttrs([]slog.Attr{})
	slog.SetDefault(logger)

	cmd.Execute()
}
