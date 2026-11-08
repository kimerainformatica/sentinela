// Package web embute o build do painel React (web/dist) no binário do
// servidor. Rode `npm run build` em web/ antes de compilar o servidor.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
