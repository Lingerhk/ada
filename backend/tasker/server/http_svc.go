package server

import (
	"net/http"
)

func RegisterHTTPMux(ts *TaskServer) http.Handler {
	mux := http.NewServeMux()

	return mux
}
