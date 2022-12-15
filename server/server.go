package server

import (
	"log"
	"net/http"

	"github.com/shashank/golang-csrf-project/middleware"
)

func StartServer(hostname string, port string) error {
	host := hostname + ":" + port

	log.Printf("Listening on: %s", host)

	handler := middleware.NewHandler()

	http.Handler("/", handler)

	return http.ListenAndServe(host, nil)
}
