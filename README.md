# JWTAuth
Simple authentication using HMAC JWTs with rotating keys

## API
### Endpoints
`POST login`  
Body: `username={user}&password={password}`  
Response:  
* Status: `200 OK`  
* Headers: `"Set-Cookie: jwt={JWT}"`  
(Note by default this will create a user if one doesn't exist)  


### Authentication
Each client has a unique [JSON Web Token](https://jwt.io/) structed as follows.
#### Header
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```
#### Payload
```
{
  "version": 1
  "username": "abc",
  "exp": {Expiration Unix Timestamp}
  "kid": base64UrlEncode(sha256(K))
}
```
#### MAC
```
HMACSHA256(
  base64UrlEncode(Header) + "." +
  base64UrlEncode(Payload),
  K
)
```
#### JWT
```
base64UrlEncode(Header) + "." +
base64UrlEncode(Payload) + "." +
base64UrlEncode(MAC)
```