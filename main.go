package main

import (
	"log"
	"net/http"
	"github.com/gorilla/mux"
)
 
func main() {
    s := mux.NewRouter().PathPrefix("/api").Subrouter()
    s.HandleFunc("/get", createTokens).Methods("POST")
    s.HandleFunc("/ref", refreshTokens).Methods("POST")
    log.Fatal(http.ListenAndServe(":8181", s))
}
