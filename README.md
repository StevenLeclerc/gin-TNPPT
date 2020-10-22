### TuNePeuxPasTest (tnppt) v1.1.2

... is a gin-middleware for a light and efficient HMAC and API_KEY auth

-----

Two Main AUth can be used :
--
####HMAC Process :
The client have to send the following headers :
```Json
{
    "HMAC_HASH": "asdasdasdasdasdadasdasdasda",
    "HMAC_TIME": 12345677654,
    "HMAC_LOGIN": "s.leclerc"
}
```

The HMAC_HASH is the concat of sha256(login + sha256(password) + time)

The middleware will check the login existence thanks to FetchUserInfos()
If Exists, it will create his own hash and compare it with the payload.
If valid, it will check the TTL (Set in `TNPPT.Security.TTL`, default to 800ms )

Then it will proceed the request.

Example of use :

```go
import (
 "tnppt" github.com/StevenLeclerc/gin-TNPPT
)

//Config the middleware before any includes within your routes
    	authMiddleware, err := tnpptMiddleware.New(&tnpptMiddleware.TNPPT{
    		//Add the FetchUserInfos, there you have to pu you database call to verify the user exists ? right ?
    		IsCredentialsValid: func(tnppt *tnpptMiddleware.TNPPT) bool {
                user, errFind := modelUser.FindUserByLogin(tnppt.PayloadHMAC.Login)
                if errFind != nil {
                    return false
                }
                tnppt.UserInfo = tnpptMiddleware.UserInfo{
                    Login:    user.Login,
                    Password: user.Password,
                }
                return true
            },
            Security: tnpptMiddleware.Security{
                TTL: 700,
            },
    	}),
})  
``` 
Then activate it within your route handler :

```go
func POSTLogin(engine *gin.Engine) gin.IRoutes {
	auth := authServices.GetAuthHAMCMiddleware()
	return engine.POST("/login", auth.ActivateHMACAuth(), func(engine *gin.Context) {
		user, errFind := modelUser.FindUserByLogin(auth.UserInfo.Login)
		if errFind != nil {
			utils.SendError(engine, http.StatusUnauthorized, utils.ErrFailedAuthentication)
			return
		}
		engine.JSON(200, user)
	})
```

-------------------------------

####APIKey Process

The client should add the HEADER: `API_KEY`

Then set the proposer process within `isCredentialsValid`

```go
func GetAuthAPIKeyMiddleware() *tnpptMiddleware.TNPPT {
	authMiddleware, err := tnpptMiddleware.New(&tnpptMiddleware.TNPPT{
		IsCredentialsValid: func(tnppt *tnpptMiddleware.TNPPT) bool {
			user, errFind := modelUser.FindUserByLogFetcherAPIKEY(tnppt.PayloadAPIKey.APIKey)
			if errFind != nil {
				return false
			}
			tnppt.UserInfo.Login = user.Login
			return true
		},
	})
	crunchyTools.HasError(err, "AUTH-HMAC UserLogin", false)
	return authMiddleware
}
``` 

Then, use it accordingly
```go
func POSTLog(engine *gin.Engine) gin.IRoutes {
	auth := authServices.GetAuthAPIKeyMiddleware()
	//TODO CREATE SIMPLE TOKEN AUTH FOR /POST LOG
	return engine.POST("/log", auth.ActivateApiKeyAuth(), func(engine *gin.Context) {
		var logReceived []modelLog.Log
		errBind := engine.BindJSON(&logReceived)
		if errBind != nil {
			utils.SendError(engine, 400, utils.ErrFailedPayload)
			return
		}
		logHandler := FetchLogHandler()
		logHandler.InsertLog(logReceived)

		engine.JSON(200, "")
	})
}
```
