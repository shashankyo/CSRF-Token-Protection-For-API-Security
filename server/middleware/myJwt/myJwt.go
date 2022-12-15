package myjwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"time"

	jwt "github.com//dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go"
	"github.com/shashank/golang-csrf-project/db/models"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey	*rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}
	verifyKey, err = jwt.ParseRSAPrivateKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}
	return nil

}

func CreateNewToken(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret, err error) {
	//generating the csrf secret
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}
	//generating the refresh token
	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)

	//generating the auth token

	authTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	return
}

func CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCsrfSecret string)(newAuthTokenString,newRefreshTokenString, newCsrfSecret string, err error) {

	if oldCsrfSecret == ""{
		log.Println("No CSRF token")
		err = errors.New("Unauthorized")
		return 
	}
	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{},func (token *jwt.Token)(interface{}, error){
		return verifykey, nil
	})  
		authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
		if !ok {
			return
		}
		if oldCsrfSecret != authTokenClaims.Csrf{
			log.Println("CSRF token does not match jwt!")
			err = errors.New("unauthorized")
			return
		}

		if authToken.valid{
			log.Println("AUth token is valid")
	
			newCsrfSecret = authTokenClaims.Csrf

			newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)

			newAuthTokenString = oldAuthTokenString
			return 
		}else if ve, ok:= err.(*jwt.ValidationError);ok{
			log.Println("Auth token is not valid")
			if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
				log.Println("Auth token is expired")
			
				newAuthTokenString,newCsrfSecret, err = updateAuthTokenString(oldRefreshTokenString,oldAuthTokenString)
				if err != nil {
					return
				}
				newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
				if err != nil {
					return
				}
				newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
				return
				}else {
					log.Println("eror is auth token ")
					err = errors.New("error is suth token")
					return 
				} else{
					log.Println("Error is auth token")
					err = errors.New("error is auth token")
					return
				}
				err =  errors.New("unauthorized ")
				return
		}

	}
func createAuthTokenString(uuid string, role string, csrfSecret string) (authTokenString, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		role,
		csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err := authJwt.SignedString(signKey)
	return
}
func createRefreshTokenString(uuid string, role string, csrfString string) (refreshTokenString string, err string) {
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:refreshJti,
			Subject:uuid,
			ExpiresAt:refreshTokenExp,
		role,
		csrfString,
	}
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)

	return
}

func updateRefreshTokenExp(oldRefreshTokenString string)(newRefreshTokenString string, err error) {
	jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return verifyKey, nil
	})
	oldRefreshTokenClaims, ok := RefreshToken.Claims.(*models.TotalClaims)
	if !ok {
		return 
	}

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

		refreshClaims := models.TokenClaims{
			jwt.StandardClaims{
				Id:oldRefreshTokenClaims.StandardClaims.Id,

				Subject:oldRefreshTokenClaims.StandardClaims.Subject,
				ExpiresAt:refreshTokenExp,
			},
			oldRefreshTokenClaims.Role,
			oldRefreshTokenClaims.Csrf,
		}

		refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

		newRefreshTokenString, err := refreshJwt.SignedString(signKey)

		return 
	}

func updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString,csrfSecret string, err error){
	
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims(), func(token *jwt.Token)(interface{}, error){
		return verifyKey, nil
	})
	refreshTokenClaims, ok := refreshTokenClaims.(*models.TokenClaims)
	if !ok {
		err = errors.New("Error reading jwt claims")
		return 
	}
	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id){
		if refreshToken.Valid {
			authToken, _:= jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
				return verifyKey, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
		
			if !ok {
				err = errors.New("error reading jwt claims")
				return 
			}

			csrfSecret, err = models.GenerateCSRFSecret()			
		
			if err != nil {
				return
			}
			createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
		
			return 
		}else {
			log.Println("refresh token has expired")
		
			db.DeleterefreshToken(refreshTokenClaims.StandardClaims.Id)
		
			err = errors.New("unauthorized")
			return 
		

		}
	}else{
		log.Println("refresh token has been revoked")
		err = errors.New("unauthorized")
		return 
	}
}

func RevokeRefreshToken(refreshToken string) error {
	//use the refresh token string that this function will recieve to get your refresh token
	refreshToken , err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return verifyKey, nil 
	})

	if err != nil {
		return errors.New("could not parse refresh token with claims")
	}


	
	
	
	//use the refresh token to get the refresh token claims
	
	refreshTokenClaims, ok := refreshToken.Claims.(*models,TokenClaims)

	if !ok {
		return errors.New("could not read refresh token claims")
	}
	//deleting the refresh token using the method in the db packages

	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

	return nil
}

func updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string)(newRefreshTokenString) {

	//get access to the refresh by using the parsewithclaims funcion
	
	refreshToken,err := jwt.ParseWithClaims(oldRefreshTokenClaims, &models.TokenClaims(), func(token *jwt.Token)(interface{},error){
		return verifyKey, nil
	})
	
	//get access to the refresh token claims
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok {
		return 
	}
	
	//refreshClaims

	refreshClaims := models.Token{
		jwt.StandardClaims{
		Id:oldRefreshTokenClaims.StandardClaims.Id,
		Subject:oldRefreshTokenClaims.StandardClaims.Subject,
		ExpiresAt:oldRefreshTokenClaims.StandardClaims.ExpiresAt,
	},
	oldRefreshTokenClaims.Role,
	newCsrfString,
	}
	//new refresh jwt



	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	//new token string
	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return 
}

func GrabUUID(authTokenString string)(string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return "", errors.New("Error fetching claims")
	})


	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)

	if !ok {
		return "", errors.New("error fetching claims")
	}

	return authTokenClaims.StandardClaims.Subject, nil
}
