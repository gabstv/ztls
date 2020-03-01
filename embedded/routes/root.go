package routes

import (
	echo "github.com/labstack/echo/v4"
)

func Root(version string) echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(200, "😎 ztls REST SERVER - "+version)
	}
}
