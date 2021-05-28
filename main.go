package main

import (
	"auth0-gin-jwt/middleware"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "From Public",
		})
	})

	r.GET("/private", middleware.CheckJWT(), middleware.JwtAuthz([]string{"create:books", "update:books", "delete:books"}, middleware.DefaultOptions()), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "From Private",
		})
	})

	r.Run(":9999")
}
