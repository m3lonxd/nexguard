// Package web embeds the static dashboard assets so cmd/server ships as a
// single binary with no external file dependencies at runtime.
package web

import "embed"

//go:embed index.html style.css app.js harita.js dunya.js detay.js kure.js sinirlar.js media/uydu-8192.jpg media/uydu-4096.jpg
var FS embed.FS
