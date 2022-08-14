package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Template is a struct for go html/template
type Template interface {
	Index(c *gin.Context)
	About(c *gin.Context)
	Stats(c *gin.Context)
	NotFound(c *gin.Context)
}

type template struct {
}

// Index is a function for index page
func (t *template) Index(c *gin.Context) {
	type feature struct {
		Icon        string
		Title       string
		Description string
	}
	f := []feature{
		{
			Icon:        "bi-shield-check",
			Title:       "Secure",
			Description: "We use a strong password hashing algorithm to store your passwords.",
		},
		{
			Icon:        "bi-server",
			Title:       "API",
			Description: "We have a robust API that allows you to manage your users and roles.",
		},
		{
			Icon:        "bi-gear-wide-connected",
			Title:       "Easy to Use",
			Description: "We have a simple and easy to use user interface.",
		},
		{
			Icon:        "bi-person-circle",
			Title:       "User Management",
			Description: "We have a robust user management system that allows you to manage your users and roles.",
		},
		{
			Icon:        "bi-patch-check",
			Title:       "Trusted",
			Description: "We ensure that your data is always safe with us.",
		},
		{
			Icon:        "bi-key",
			Title:       "Asymmetric Encryption",
			Description: "We use asymmetric encryption to issue tokens.",
		},
		{
			Icon:        "bi-code",
			Title:       "Up to Date",
			Description: "We keep our dependencies up to date and squash bugs as they come!",
		},
		{
			Icon:        "bi-file-text",
			Title:       "Fully Open Source",
			Description: "We are fully open source and licensed under the MIT license.",
		},
		{
			Icon:        "bi-heart",
			Title:       "Made with Love",
			Description: "We love to create open source software, and we hope you will too!",
		},
	}
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title":     "Auth — Home",
		"home":      "active",
		"feature":   f,
		"copyright": "Copyright © 2022 mrinjamul. All rights reserved.",
	})
}

// About is a function for about page
func (t *template) About(c *gin.Context) {
	c.HTML(http.StatusOK, "about.html", gin.H{
		"title":     "Auth — About",
		"about":     "active",
		"copyright": "Copyright © 2022 mrinjamul. All rights reserved.",
	})
}

// Stats is a function for stats page
func (t *template) Stats(c *gin.Context) {
	c.HTML(http.StatusOK, "stats.html", gin.H{
		"title":     "Auth — Stats",
		"copyright": "Copyright © 2022 mrinjamul. All rights reserved.",
	})
}

// NotFound is a function for not found page
func (t *template) NotFound(c *gin.Context) {
	c.HTML(http.StatusNotFound, "404.html", gin.H{
		"title":     "Auth — Not Found",
		"copyright": "Copyright © 2022 mrinjamul. All rights reserved.",
	})
}

// NewTemplate is a function for new template
func NewTemplate() Template {
	return &template{}
}
