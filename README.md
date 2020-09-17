### TuNePeuxPasTest (tnppt) v1.0.0

... is a gin-middleware for a light and efficient HMAC auth

-----

Process :
The client hve to send a body JSON with :
```json
{
    "TNPPT_HASH": "asdasdasdasdasdadasdasdasda",
    "TNPPT_TIME": 12345677654,
    "TNPPT_LOGIN": "s.leclerc"
}
```

The TNPPT_HASH is the concat of sh256(login + password + time)

The middleware will check the login existance thanks to FetchUserInfos()
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
    		FetchUserInfos: func(tnppt *tnpptMiddleware.TNPPT) bool {
    			userFromDB, errFind := database.getUserByLogin(tnppt.Payload.Login)
    
    			if errFind != nil {
    				return false
    			}
    			tnppt.UserInfo = tnpptMiddleware.UserInfo{
    				Login:    userFromDB.Login,
    				Password: userFromDB.HashedPassword,
    			}
    			return true
    		},
    	}),
        Security: tnppt.Security{
    	    TTL: 700,
    	},
})  
``` 
