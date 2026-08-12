//go:build !android

package main

import (
	"context"
	"os"

	"cottendns-go/internal/client"
	"cottendns-go/internal/clientui"
	"golang.org/x/term"
)

func canPromptStartup() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

func runClient(ctx context.Context, app *client.Client, intro func()) error {
	if clientui.ShouldUse(app.TerminalUIMode()) {
		return clientui.Run(ctx, app, intro)
	}
	intro()
	return app.Run(ctx)
}
