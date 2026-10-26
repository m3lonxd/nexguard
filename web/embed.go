// Package web embeds the static dashboard assets so cmd/server ships as a
// single binary with no external file dependencies at runtime.
package web

import "embed"

//go:embed index.html style.css app.js
var FS embed.FS
