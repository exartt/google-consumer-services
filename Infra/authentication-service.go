package autentication

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/calendar/v3"
	"io/ioutil"
	"net/http"
)

const (
	tokenStash     = "/tmp/gcal-token"
	credentialPath = "../credential.json"
)

func novoCliente() (*http.Client, error) {
	credentialsB, err := ioutil.ReadFile(credentialPath)
	if err != nil {
		return nil, err
	}

	config, err := google.ConfigFromJSON(credentialsB, calendar.CalendarReadonlyScope)

	token, err := getToken(config)
	if err != nil {
		return nil, err
	}
	client := config.Client(context.Background(), token)

	return client, nil
}

func getToken(config *oauth2.Config) (*oauth2.Token, error) {
	stashedToken, err := getStashedToken()
	if err != nil {
		fmt.Printf("Erro na tentativa de coletar o stashed token: %s \n", err)
		token, err := getNewToken(config)
		if err != nil {
			return token, err
		}
		stashToken(token)
		return token, nil
	}
	return stashedToken, nil
}

func getStashedToken() (*oauth2.Token, error) {
	tokenB, err := ioutil.ReadFile(tokenStash)
	if err != nil {
		return &oauth2.Token{}, err
	}
	if len(tokenB) == 0 {
		return &oauth2.Token{}, fmt.Errorf("token de autorização vazio")
	}
	var token oauth2.Token
	err = json.Unmarshal(tokenB, &token)
	return &token, nil
}

func stashToken(token *oauth2.Token) error {
	tokenB, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(tokenStash, tokenB, 0644)
}

func getNewToken(config *oauth2.Config) (*oauth2.Token, error) {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Vá para o seguinte link no seu navegador e digite o código: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		return &oauth2.Token{}, fmt.Errorf("não foi possível ler o código te autorização: %v", err)
	}

	token, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		return &oauth2.Token{}, fmt.Errorf("não foi possível adquirir o token pela web: %v", err)
	}
	return token, err
}
