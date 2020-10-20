module app

go 1.15

replace (
	github.com/kataras/jwt => C:/megadrive/kataras/jwt
	github.com/kataras/iris/v12 => C:/mygopath/src/github.com/kataras/iris
)

require (
	github.com/kataras/iris/v12 v12.2.0-alpha.0.20201018152601-b335ab9c78d2
	github.com/kataras/jwt v0.0.0-00010101000000-000000000000
)
