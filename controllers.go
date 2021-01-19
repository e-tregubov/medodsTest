package main

import (
	"fmt"
	"context"
	"net/http"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)
type tokens struct{
	AT string `json:"AccessToken"`
	RT string `json:"RefreshToken"`
}
type post struct{
	GUID string `json:"guid"`
	RT []byte `json:"rt"`
}
var (
	client,_ = mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
// DB = collection
	DB = client.Database("medods").Collection("users")
)

// createTokens
func createTokens(w http.ResponseWriter, r *http.Request){
	guid := r.FormValue("guid")
	var user post
	if DB.FindOne(context.TODO(), bson.M{"guid":guid}).Decode(&user) != nil{
		AT := createAT(guid)
		RT := createRT(AT)
		hashedRT,_ := bcrypt.GenerateFromPassword([]byte(RT), 12)
		_,_ = DB.InsertOne(context.TODO(), post{GUID:guid, RT:hashedRT})
		json.NewEncoder(w).Encode(tokens{AT:AT, RT:RT})
	} else {fmt.Fprint(w, "Error: user exists!")}
}

// refreshTokens
func refreshTokens(w http.ResponseWriter, r *http.Request){
	AT,RT := r.FormValue("at"), r.FormValue("rt")
	guid := getATguid(AT)
	if guid != ""{
		if isRTvalid(AT,RT){
			var post post
			if DB.FindOne(context.TODO(), bson.M{"guid":guid}).Decode(&post) == nil{
				if bcrypt.CompareHashAndPassword(post.RT, []byte(RT)) == nil{
					AT := createAT(guid)
					RT := createRT(AT)
					hashedRT,_ := bcrypt.GenerateFromPassword([]byte(RT), 12)
					_,_ = DB.UpdateOne(
						context.Background(),
						bson.M{"guid":guid},
						bson.M{"$set":bson.M{"rt":(hashedRT)}},
					)
					json.NewEncoder(w).Encode(tokens{AT:AT, RT:RT})
				} else {fmt.Fprint(w, "Reauthentication: no refresh-token found!")}
			} else {fmt.Fprint(w, "Reauthentication: no such user")}
		} else {fmt.Fprint(w, "Reauthentication: invalid refresh-token or tokens pair!")}
	} else {fmt.Fprint(w, "Reauthentication: invalid access-token!")}
}
