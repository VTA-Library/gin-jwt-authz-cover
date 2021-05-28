## Usage
If it does not have even one of the specified permissions, it will return a 403 status code. This will work when checkAllScopes is true by default.

```go
r.GET("/private", middleware.CheckJWT(), middleware.JwtAuthz([]string{"create:books", "update:books", "delete:books"}, middleware.DefaultOptions()), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "From Private",
		})
	})
```

## export environment variable
```shell
$ export $(cat .env | grep -v ^# | xargs)
```

## Write environment variables in `.env`
```text
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_IDENTIFIER=YOUR_AUTH0_IDENTIFIER
```