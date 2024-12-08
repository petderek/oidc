package oidc_backend

import "os"

type Config interface {
	Get(s string) string
}

type EnvConfig struct {
	PanicOnEmpty bool
}

func (c *EnvConfig) Get(s string) string {
	r := os.Getenv(s)
	if c.PanicOnEmpty && r == "" {
		panic("expected env " + s + " to be set")
	}
	return r
}
