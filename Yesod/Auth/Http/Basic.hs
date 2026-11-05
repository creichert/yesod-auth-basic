{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE OverloadedStrings #-}

-- | HTTP Basic authentication for Yesod. Use HTTPS.
--
-- Import this module and set @maybeAuthId@ in your existing @YesodAuth@
-- instance, where @AuthId App = Text@:
--
-- @
-- maybeAuthId = defaultMaybeBasicAuthId checkCredentials defaultAuthSettings
-- @
--
-- Supply an application-specific credential checker:
--
-- @
-- checkCredentials :: ByteString -> ByteString -> IO Bool
-- checkCredentials username password =
--     pure (username == "user" && password == "secret") -- Example only.
-- @
--
-- The checker receives decoded bytes unchanged. Usernames must be UTF-8;
-- password encoding is up to the checker. Both successful and failed results
-- are cached for the current request, never across HTTP requests.
--
-- Route authorization and HTTP challenges belong to your application:
--
-- @
-- instance Yesod App where
--     authRoute _ = Nothing -- Return 401 instead of redirecting to a login page.
--
--     isAuthorized ProtectedR _ = do
--         user <- maybeAuthId
--         pure $ maybe AuthenticationRequired (const Authorized) user
--     isAuthorized _ _ = pure Authorized
--
--     errorHandler NotAuthenticated = do
--         addHeader "WWW-Authenticate" "Basic realm=\"API\", charset=\"UTF-8\""
--         defaultErrorHandler NotAuthenticated
--     errorHandler err = defaultErrorHandler err
-- @
--
-- This produces a 401 response for missing or invalid credentials on
-- @ProtectedR@. See <https://www.rfc-editor.org/rfc/rfc7617 RFC 7617>.

module Yesod.Auth.Http.Basic
       (
          -- * Authentication
         defaultMaybeBasicAuthId

         -- * Settings
       , AuthSettings
       , authRealm
       , defaultAuthSettings
       ) where

import qualified Data.ByteString        as BS
import qualified Data.Text.Encoding     as T

import Data.ByteString        (ByteString)
import Data.ByteString.Base64 (decode)
import Data.Text              (Text)
import Data.Typeable
import Data.Word8             (toLower, _colon, _space)
import Network.Wai
import Prelude
import Yesod                  hiding (Header)


-- | Reserved authentication settings. HTTP challenges are application-managed.
newtype AuthSettings = AuthSettings {
      authRealm :: Text
      -- ^ Reserved realm value; does not generate a @WWW-Authenticate@ header.
    } deriving (Eq, Show)

-- | Default reserved settings, with @authRealm = "Realm"@.
defaultAuthSettings :: AuthSettings
defaultAuthSettings = AuthSettings { authRealm = "Realm" }

-- | A request-local authentication result, including failed authentication.
newtype CachedBasicAuthId a
  = CachedBasicAuthId { unCached :: Maybe a }
    deriving Typeable


-- | Application-supplied checker for decoded username and password bytes.
type CheckCreds = ByteString
                  -> ByteString
                  -> IO Bool

-- | Look up HTTP Basic credentials and return the verified UTF-8 username.
--
-- Use as @maybeAuthId@ in a @YesodAuth@ instance with @AuthId@ equal to 'Text'.
-- Missing or malformed headers, invalid UTF-8 usernames, and rejected
-- credentials return 'Nothing'. The checker receives the decoded bytes
-- without trimming; passwords may contain colons.
--
-- Both successful and failed results are cached within the current request.
-- This function does not enforce route access or generate a challenge.
defaultMaybeBasicAuthId
  :: MonadHandler m
  => CheckCreds
  -> AuthSettings
  -> m (Maybe Text)
defaultMaybeBasicAuthId auth cfg =
    cachedAuth $ waiRequest >>= maybeBasicAuthId auth cfg


-- | Cache the authentication result for the current request.
cachedAuth
  :: (MonadHandler m)
  => m (Maybe Text)
  -> m (Maybe Text)
cachedAuth = fmap unCached . cached . fmap CachedBasicAuthId


-- | Decode and check HTTP Basic credentials for one request.
--
-- The scheme is case-insensitive and followed by one or more ASCII spaces.
-- Credentials must be strictly Base64-encoded (RFC 4648); malformed input is
-- rejected before invoking the credential checker, not silently repaired.
--
-- Request-local caching is provided by 'defaultMaybeBasicAuthId'.
maybeBasicAuthId
  :: (MonadHandler m)
  => CheckCreds
  -> AuthSettings
  -> Request
  -> m (Maybe Text)
maybeBasicAuthId checkCreds _ req =
    case authorization of
      Just (strategy, userpass)
        | BS.map toLower strategy == "basic" ->
              authorizeCredentials $ BS.dropWhile (== _space) userpass
        | otherwise -> return Nothing
      _ -> return Nothing
  where
    authorization = BS.break (== _space)
                    <$> lookup "Authorization" (requestHeaders req)
    authorizeCredentials encoded =
      case decode encoded of
        Left _ -> return Nothing
        Right decoded ->
          let (username, password') = BS.break (== _colon) decoded
          in case BS.uncons password' of
              Nothing -> return Nothing
              Just (_,password) -> do
                authorized <- liftIO $ checkCreds username password
                return $ if authorized
                           then either (const Nothing) Just $ T.decodeUtf8' username
                           else Nothing
