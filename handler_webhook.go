package main

import (
	"chirpy/internal/auth"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

func (cfg *apiConfig) handlerPolkaWebhook(w http.ResponseWriter, r *http.Request) {

	apiKey, err := auth.GetAPIKey(r.Header)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find api key", err)
		return
	}
	if apiKey != cfg.polkaKey {
		respondWithError(w, http.StatusUnauthorized, "API key is invalid", err)
		return
	}

	type Data struct {
		UserID uuid.UUID `json:"user_id"`
	}

	type parameters struct {
		Event string `json:"event"`
		Data  Data   `json:"data"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters", err)
		return
	}

	if params.Event == "user.upgraded" {
		err = cfg.db.UpdateUserChirpyRed(r.Context(), params.Data.UserID)

		if err != nil {
			respondWithError(w, http.StatusNotFound, "Couldn't upgrade user", err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}

}
