// markdown_render.go — wrappers that delegate to internal/mdserve.
package handlers

import (
	"net/http"

	"github.com/MuyleangIng/MekongTunnel/internal/mdserve"
)

func renderMarkdown(src string) string         { return mdserve.RenderMarkdown(src) }
func renderMarkdownPage(t, b, n string) string { return mdserve.RenderPage(t, b, n) }
func buildNav(root, cur string) string         { return mdserve.BuildNav(root, cur) }
func markdownDeployServer(root string) http.Handler { return mdserve.Handler(root) }
