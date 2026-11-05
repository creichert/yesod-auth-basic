# Yesod HTTP Basic Authentication

[![Hackage](https://img.shields.io/hackage/v/yesod-auth-basic.svg)](https://hackage.haskell.org/package/yesod-auth-basic)

HTTP Basic Auth for Yesod applications. Use HTTPS.

## Usage

Import `Yesod.Auth.Http.Basic`, then add this override to your existing
`YesodAuth` instance, where `AuthId App = Text`:

```haskell
maybeAuthId = defaultMaybeBasicAuthId checkCredentials defaultAuthSettings
```

Supply your application's credential checker. For example:

```haskell
checkCredentials :: ByteString -> ByteString -> IO Bool
checkCredentials username password =
    pure (username == "user" && password == "secret") -- Example only.
```

The checker receives decoded bytes unchanged. Usernames must be valid UTF-8
because the authenticated ID is `Text`; password encoding is up to the checker.
Successful and failed results are cached **only within the current request**.

## Protect routes and send a challenge

The helper does not enforce access or send HTTP challenges. Configure these in
your application's `Yesod` instance (using your own route names):

```haskell
instance Yesod App where
    authRoute _ = Nothing -- Return 401 instead of redirecting to a login page.

    isAuthorized ProtectedR _ = do
        user <- maybeAuthId
        pure $ maybe AuthenticationRequired (const Authorized) user
    isAuthorized _ _ = pure Authorized

    errorHandler NotAuthenticated = do
        addHeader "WWW-Authenticate" "Basic realm=\"API\", charset=\"UTF-8\""
        defaultErrorHandler NotAuthenticated
    errorHandler err = defaultErrorHandler err
```

Missing or invalid credentials on `ProtectedR` produce a 401 response.
`authRealm` is currently reserved; set the challenge's realm in your handler.

## Requests

Let your HTTP client construct the header:

```sh
curl --user 'user:secret' https://example.com/protected
```

```text
Authorization: Basic <base64(username:password)>
```

`Basic` is case-insensitive and followed by ASCII spaces. Use standard Base64
with required padding, without quotes or embedded whitespace. Malformed headers
are rejected, not repaired. Decoded credentials are not trimmed; colons after
the first delimiter remain part of the password.
