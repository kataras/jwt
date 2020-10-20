package main

import (
	"time"

	"github.com/kataras/iris/v12"
	"github.com/kataras/jwt"
)

var mySecret = []byte("secret")

// generate token to use.
func getTokenHandler(ctx iris.Context) {
	now := time.Now()

	token, err := jwt.Token(jwt.HS256, mySecret, iris.Map{
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
		"foo": "bar",
	})

	if err != nil {
		ctx.StopWithError(iris.StatusInternalServerError, iris.PrivateError(err))
		return
	}

	tokenString := string(token)

	ctx.HTML(`Token: ` + tokenString + `<br/><br/>
<a href="/protected?token=` + tokenString + `">/protected?token=` + tokenString + `</a>`)
}

func myAuthenticatedHandler(ctx iris.Context) {
	token := ctx.URLParam("token")
	if token == "" {
		ctx.StopWithStatus(iris.StatusUnauthorized)
		return
	}

	var claims iris.Map
	_, err := jwt.VerifyToken(jwt.HS256, mySecret, time.Now(), []byte(token), &claims)
	if err != nil {
		ctx.StopWithError(iris.StatusUnauthorized, iris.PrivateError(err))
		return
	}

	ctx.Writef("This is an authenticated request\n\n")

	ctx.Writef("foo=%s\n", claims["foo"])
	// for key, value := range foobar {
	// 	ctx.Writef("%s = %s", key, value)
	// }
}

func main() {
	app := iris.New()
	app.OnAnyErrorCode(func(ctx iris.Context) {
		if err := ctx.GetErr(); err != nil {
			ctx.WriteString(err.Error())
			return
		}

		ctx.WriteString(iris.StatusText(ctx.GetStatusCode()))
	})

	app.Get("/", getTokenHandler)
	app.Get("/protected", myAuthenticatedHandler)
	app.Get("/no-protected", func(ctx iris.Context) {
		ctx.Writef("This is an authenticated request\n\n")
		ctx.Writef("foo=%s", "bar")
	})

	app.Listen(":8080")
}
