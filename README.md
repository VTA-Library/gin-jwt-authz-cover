
## export environment variable
```shell
$ export $(cat .env | grep -v ^# | xargs)
```

## Write environment variables in `.env`
```text
AUTH0_DOMAIN=YOUR_AUTH0_DOMAIN
AUTH0_IDENTIFIER=YOUR_AUTH0_IDENTIFIER
```