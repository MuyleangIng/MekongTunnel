// Package response provides JSON HTTP response helpers.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package response

import (
	"encoding/json"
	"log"
	"net/http"
)

// Response is the standard envelope for every API response.
type Response struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// JSON writes v as a JSON body with the given HTTP status code.
func JSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[response] encode error: %v", err)
	}
}

// Success sends a 200 OK response wrapping data.
func Success(w http.ResponseWriter, data any) {
	JSON(w, http.StatusOK, Response{OK: true, Data: data})
}

// Created sends a 201 Created response wrapping data.
func Created(w http.ResponseWriter, data any) {
	JSON(w, http.StatusCreated, Response{OK: true, Data: data})
}

// Error sends an error response with the supplied HTTP status and message.
func Error(w http.ResponseWriter, statusCode int, msg string) {
	JSON(w, statusCode, Response{OK: false, Error: msg})
}

// BadRequest sends a 400 response.
func BadRequest(w http.ResponseWriter, msg string) {
	Error(w, http.StatusBadRequest, msg)
}

// Unauthorized sends a 401 response.
func Unauthorized(w http.ResponseWriter, msg string) {
	Error(w, http.StatusUnauthorized, msg)
}

// Forbidden sends a 403 response.
func Forbidden(w http.ResponseWriter, msg string) {
	Error(w, http.StatusForbidden, msg)
}

// NotFound sends a 404 response.
func NotFound(w http.ResponseWriter, msg string) {
	Error(w, http.StatusNotFound, msg)
}

// Conflict sends a 409 response.
func Conflict(w http.ResponseWriter, msg string) {
	Error(w, http.StatusConflict, msg)
}

// NoContent sends a 204 No Content response.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// InternalError logs the real error and sends a generic 500 to the client.
func InternalError(w http.ResponseWriter, err error) {
	log.Printf("[api] internal error: %v", err)
	Error(w, http.StatusInternalServerError, "internal server error")
}
