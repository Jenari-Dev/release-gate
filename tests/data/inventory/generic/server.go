package main

import "log"

type Customer struct {
	Email    string `json:"email"`
	Passport string `json:"passport_number"`
	Notes    string `json:"internal_notes"`
}

func lookup(c Customer) {
	log.Printf("lookup email=%s", c.Email)
}
