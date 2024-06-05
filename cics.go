package main

import (
	"ibm/container_cryptography_scanner/cmd"
	"log/slog"
	"os"
)

func main() {
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	})

	logger := slog.New(logHandler)

	logger.Handler().WithAttrs([]slog.Attr{})

	slog.SetDefault(logger)

	cmd.Execute()
}
