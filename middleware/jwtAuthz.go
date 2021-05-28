package middleware

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"reflect"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gin-gonic/gin"
)

type Options struct {
	failWithError  bool
	customScopeKey string
	customUserKey  string
	checkAllScopes bool
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		aud := os.Getenv("AUTH0_IDENTIFIER")
		convAud, ok := token.Claims.(jwt.MapClaims)["aud"].([]interface{})
		if !ok {
			strAud, ok := token.Claims.(jwt.MapClaims)["aud"].(string)
			if !ok {
				return token, errors.New("Invalid audience.")
			}
			if strAud != aud {
				return token, errors.New("Invalid audience.")
			}
		} else {
			for _, v := range convAud {
				if v == aud {
					break
				} else {
					return token, errors.New("Invalid audience.")
				}
			}
		}
		iss := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		if !checkIss {
			return token, errors.New("Invalid issuer.")
		}

		cert, err := getPemCert(token)
		if err != nil {
			panic(err.Error())
		}

		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	},
	SigningMethod: jwt.SigningMethodRS256,
})

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}

func DefaultOptions() Options {
	return Options{
		failWithError:  true,
		customScopeKey: "",
		customUserKey:  "",
		checkAllScopes: true,
	}
}

func CheckJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtMid := *jwtMiddleware
		if err := jwtMid.CheckJWT(c.Writer, c.Request); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

func JwtAuthz(expectedScopes []string, options Options) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.Request.Context().Value("user")

		log.Println(reflect.TypeOf(user.(*jwt.Token).Claims.(jwt.MapClaims)["permissions"]))

		log.Println(reflect.TypeOf(InterfaceSliceConversion(user.(*jwt.Token).Claims.(jwt.MapClaims)["permissions"].([]interface{}))))

		if len(expectedScopes) == 0 {
			c.Next()
			return
		}

		allowed := false
		if options.checkAllScopes {
			allowed = every(expectedScopes, InterfaceSliceConversion(user.(*jwt.Token).Claims.(jwt.MapClaims)["permissions"].([]interface{})))
		} else {
			allowed = some(expectedScopes, InterfaceSliceConversion(user.(*jwt.Token).Claims.(jwt.MapClaims)["permissions"].([]interface{})))
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient scope",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func InterfaceSliceConversion(interfaceSlice []interface{}) []string {
	stringSlice := make([]string, len(interfaceSlice))
	for i, v := range interfaceSlice {
		stringSlice[i] = v.(string)
	}
	return stringSlice
}

func every(expectedScopes []string, userScopes []string) bool {
	check := false
	for _, v := range expectedScopes {
		if !includes(userScopes, v) {
			check = false
			break
		} else {
			check = true
		}
	}
	return check
}

func some(expectedScopes []string, userScopes []string) bool {
	check := false
	for _, v := range expectedScopes {
		if includes(userScopes, v) {
			check = true
		}
	}
	return check
}

func includes(userScopes []string, scope string) bool {
	for _, v := range userScopes {
		if v == scope {
			return true
		}
	}

	return false
}
