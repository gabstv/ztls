package middlewares

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ReneKroon/ttlcache"
	echo "github.com/labstack/echo/v4"
)

type rlitem struct {
	IP    string
	Route string
	Count uint64
}

func RateLimiter(max uint64, period time.Duration) echo.MiddlewareFunc {
	if period <= 0 {
		panic("invalid period")
	}
	if max == 0 {
		panic("invalid max")
	}
	cache := ttlcache.NewCache()
	cache.SkipTtlExtensionOnHit(true)
	cache.SetTTL(period)
	xx := int64((time.Duration(max) * time.Hour) / period)
	xxs := fmt.Sprint(xx)

	preph := func(h http.Header, n uint64) {
		h.Set("X-RateLimit-Limit", xxs)
		h.Set("X-RateLimit-Remaining", fmt.Sprint(max-n))
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rli := &rlitem{c.RealIP(), c.Path(), 0}
			if _, ok := cache.Get(rli.IP); !ok {
				rli.Count = 1
				cache.Set(rli.IP, rli)
				preph(c.Response().Header(), 1)
				return next(c)
			}
			ci, ok := cache.Get(c.RealIP())
			if !ok {
				return c.String(500, "failed to setup TTL")
			}
			rli = ci.(*rlitem)
			if rli.Count+1 >= max {
				preph(c.Response().Header(), max)
				return c.String(429, "too many requests")
			}
			rli.Count = rli.Count + 1
			cache.Set(rli.IP, rli)
			preph(c.Response().Header(), rli.Count)
			return next(c)
		}
	}
}
