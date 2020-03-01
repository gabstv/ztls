package routes

import (
	echo "github.com/labstack/echo/v4"
)

type CSRFunc func(csr []byte) (cert []byte, err error)

func PostCSR(csrfn CSRFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		d := struct {
			CSR string `json:"csr" xml:"csr" form:"csr"`
		}{}
		if err := c.Bind(&d); err != nil {
			return c.String(400, err.Error())
		}
		cert, err := csrfn([]byte(d.CSR))
		if err != nil {
			return c.String(400, err.Error())
		}
		return c.String(200, string(cert))
	}
}

func GetCA(ca []byte) echo.HandlerFunc {
	return func(c echo.Context) error {
		return c.String(200, string(ca))
	}
}
