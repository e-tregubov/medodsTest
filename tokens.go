package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
	"github.com/dgrijalva/jwt-go"
)

// data
type data struct {
	Data string
	Exp int
}
var secretATkey, secretRTkey string = "secretATkey", "secretRTkey"

// createAT
func createAT(guid string) string{
	return calcJWT(jwt.NewWithClaims(jwt.SigningMethodHS512,
		jwt.MapClaims{"data": guid,
		              "exp" : time.Now().Add(time.Minute * 15).Unix()}), secretATkey)
}
// createRT
func createRT(AT string) string{
	return calcJWT(jwt.NewWithClaims(jwt.SigningMethodHS512,
			jwt.MapClaims{"data": strings.Split(AT,".")[2][:10],
						  "exp" : time.Now().Add(time.Hour * 24).Unix()}), secretRTkey)
}
// calcJWT
func calcJWT(headAndPayload *jwt.Token, key string) string{
	JWT,_ := headAndPayload.SignedString([]byte(key))
	return JWT
}
// getATguid
func getATguid(AT string) string{
	if isJWT(AT){
		var data data = getJWTpayload(AT)
		if AT == calcJWT(jwt.NewWithClaims(jwt.SigningMethodHS512,
				jwt.MapClaims{"data": data.Data,
							  "exp" : data.Exp}), secretATkey){
								  return data.Data
								}
		}
	return ""
}
// isRTvalid
func isRTvalid(AT, RT string) bool{
	if isJWT(RT){
		var data data = getJWTpayload(RT)
		if data.Exp > int(time.Now().Unix()){
			if RT == calcJWT(jwt.NewWithClaims(jwt.SigningMethodHS512,
				jwt.MapClaims{"data": strings.Split(AT,".")[2][:10],
							  "exp" : data.Exp}), secretRTkey){
								  return true
								}
		}	
	}
	return false
}
// isJWT
func isJWT(jwt string) bool{
	if len(strings.Split(jwt,".")) == 3 {return true}
	return false
}
// getJWTpayload
func getJWTpayload(JWT string) data{
	var data data
	payload,_ := base64.RawStdEncoding.DecodeString(strings.Split(JWT,".")[1])
	json.Unmarshal(payload, &data)
	return data
}
