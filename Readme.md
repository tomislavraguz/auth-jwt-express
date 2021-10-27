NOTICE: This library is a new project, use with caution. I plan to review and test it
when I catch some time.

A simple library aiming to make use of JWT for sessions easier for simpler apps and exposing some of the internal functions to make advanced use cases easier.

The JWT is created using the **generate** function, the params it was called with and the original issuing time will be stored alongside the data in the JWT to avoid the need for refresh tokens. After the **dataRefreshIntervalInSeconds** period passes the middleware will call the function with the stored parameters and attempt to refresh the data. 

Throwing an error inside the getJWTData function will remove the cookie it is stored in. This enables you to do eg. logout from all devices by checking if the oiat(original issuing time) is older than when the user logged out from all the devices inside the getJWTData, you would then throw an error deleting the cookie and logging the user out from that machine. This enables you to easily deal with the revocation scenarios which are often problematic with JWT.

When CSRF protection is configured the middleware will reject requests not conforming to the configured policies for conventionaly unsafe HTTP methods by default. You can disable this by setting **disableMiddlewareRequestVerification** to true in the middleware options if you are running for eg a GraphQL server and all you requests are POST. You can then manually implement
the same pattern before your mutations:

```ts
const csrfErrors = await req.authJWT.checkCSRF();
if(csrfErrors.length) { throw Error('CSRFViolation') }
```

Since the getJWTData calls are made only after the data expires(for most applications 15 minutes should be a good value) it provides a good balance of performance and security. The optional **expandSession** function is provided, the middleware will call it with the JWT data as the parameter and its return value will set as session data. You can use this for sessions which are impractical to fully store in the JWT itself. If using this option with typescript the third generic parameter of the middleware generating function will be the type of the returned data.

Take care that everything stored in the JWT is serializable, including the getJWTData function params.

If using csrf tokens you can customize how they are extracted from the request in the middleware options, by default they are:
```ts
getCSRFTokenFromRequest = (req: ERequest) => req.body["CSRFToken"]
getCSRFTokenFromSession = (req: ERequest) => req.authJWT.getData().CSRFToken
```

Here is an example using mongoose:

```ts
//JWTAuth.ts
import { ObjectId } from  'bson';
import { JWTAuth, authJWTExpress, AuthJWT } from  'auth-jwt-express'
import { User } from  '../segments/user/user.model';

export  const  jwtAuth = new  JWTAuth<string, UserSession>({
  ////secret generated via > openssl rand -base64 64
  secret:  "fnh0X8EK8Qi+g8Rye6/AJ3B/GqODvihkrkHXpEl3eC+TD1yPT+EsJ6aMmzF8bFmSnhjQGjFMGAsTdHHnjDxH6Q==",
  getJWTData:  async (userId: string, oiat: number) => {
    const  userDoc = await  User.findById(new ObjectId(userId))
    if(!userDoc) {
      throw  Error(`User ${userID} not found`)
    }
    return  userDoc.toObject({ virtuals:  true });
  },
  dataRefreshIntervalInSeconds:  15 * 60,
  cookieConfig: {
    useCookie:  true,
    CSRFProtection: {
      customHeader: { active:  true }
      /* 
      you can choose from several defense techniques for your use case, 
      we use customHeader here making our api only available through AJAX calls
      Read more at owasp.org
      */
    }
  }
})

export  const  jwtMiddleware = authJWTExpress(jwtAuth)

export  interface  UserSession {
  _id: ObjectId
  email: string
}

declare  global {
  namespace  Express {
    interface  Request {
      authJWT: AuthJWT<string, UserSession>
    }
  }
}
```

```ts
...express app code

app.use(jwtMiddleware)

app.post('/login', async (req, res) => {
  ...auth logic
  const userId = "615f742e884c0dc546ab747a"
  const { data } = await req.authJWT.generate(userId);
  res.json(data)
})

app.get('/me',async (req, res) => {
  const user = await req.authJWT.getData()
  res.json(user)
})
```
```ts
/*
since we configured a default custom header defense policy we now need to add the header 
to our unsafe HTTP method requests
*/
await fetch('/api/login', {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest"
    },
    body: JSON.stringify({ email: "tomislav@raguz.com", password: "********" })
})
```
