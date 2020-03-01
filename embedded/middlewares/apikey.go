package middlewares

import "github.com/labstack/echo/v4"

func APIKey(key string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().Header.Get("X-API-KEY") != key {
				return c.String(401, "invalid/missing header X-API-KEY")
			}
			return next(c)
		}
	}
}