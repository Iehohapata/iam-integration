package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	ctx          context.Context
)

func main() {
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{Transport: customTransport}
	ctx = context.WithValue(context.Background(), oauth2.HTTPClient, client)

	issuer := os.Getenv("OIDC_ISSUER")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	redirectURL := os.Getenv("REDIRECT_URL")

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		fmt.Printf("OIDC discovery failed: %v\n", err)
	} else {
		oauth2Config = oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
		verifier = provider.Verifier(&oidc.Config{ClientID: clientID})
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/user-info", handleUserInfo)

	fmt.Println("Web service is running on port 8080...")
	http.ListenAndServe(":8080", nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if verifier == nil {
		http.Error(w, "OIDC Provider not fully initialized. Check credentials.", http.StatusInternalServerError)
		return
	}
	state := "random-state-protection"
	url := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Missing id_token in response", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/?token="+rawIDToken, http.StatusFound)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "401 Unauthorized: No token found", http.StatusUnauthorized)
		return
	}

	idToken, err := verifier.Verify(ctx, cookie.Value)
	if err != nil {
		http.Error(w, "401 Unauthorized: Invalid token signature", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}
