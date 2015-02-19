-- | A Yesod middleware for <<http://tools.ietf.org/html/rfc1945#section-11.1 HTTP Basic Authentication>>
--
-- This middleware performs a single authentication lookup
-- per request and uses the Yesod request-local caching
-- mechanisms to store valid auth credentials found in the
-- Authorization header.
--
--
-- The recommended way to use this module is to override the
-- @maybeAuthId@ to @defaultMaybeBasicAuthId@ and supply a
-- lookup function.
--
-- @
-- instance YesodAuth App where
--     type AuthId App = Text
--     getAuthId = return . Just . credsIdent
--     maybeAuthId = defaultMaybeBasicAuthId checkCreds
--       where
--         checkCreds = \k s -> return $ (k == "user")
--                                    && (s == "secret")
-- @
--
--
-- WWW-Authenticate challenges are currently not implemented.
-- The current workaround is to override the error handler:
--
-- @
-- instance Yesod App where
--   errorHandler NotAuthenticated = selectRep $
--       provideRep $ do
--         addHeader "WWW-Authenticate" $ T.concat
--               [ "RedirectJSON realm=\"Realm\", param=\"myurl.com\"" ]
--         -- send error response here
--         ...
--   errorHandler e = defaultErrorHandler e
--   ...
-- @
--
--
-- Proper response status on failed authentication is not implemented.
-- The current workaround is to override the 'Yesod' typeclass
-- @isAuthorized@ function to handle required auth routes. e.g.
--
-- @
-- instance Yesod App where
--   isAuthorized SecureR _   =
--     maybeAuthId >>= return . maybe AuthenticationRequired (const Authorized)
--   isAuthorized _ _         = Authorized
-- @
--

{-# LANGUAGE DeriveDataTypeable    #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}

module Yesod.Auth.Http.Basic
       (
         -- * Drop in replace for maybeAuthId.
         defaultMaybeBasicAuthId

       -- The AuthSettings will not be exported until
       -- features are implemented which actually uses
       -- them
       --
       -- , AuthSettings
       -- , authRealm
       -- , defaultAuthSettings
       ) where

import           Control.Applicative
import           Control.Monad.Catch    (MonadThrow)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import           Data.ByteString.Base64 (decodeLenient)
import           Data.Text              (Text)
import qualified Data.Text.Encoding     as T
import           Data.Typeable
import           Data.Word8             (isSpace, toLower, _colon)
import           Network.Wai
import           Yesod                  hiding (Header)


-- | Authentication Settings
data AuthSettings = AuthSettings
    {
      authRealm :: Text
    }

-- | ready-to-go 'AuthSettings' which can be used
defaultAuthSettings :: AuthSettings
defaultAuthSettings = AuthSettings { authRealm = "Realm" }


-- | Cachable basic authentication credentials
newtype CachedBasicAuthId a
  = CachedBasicAuthId { unCached :: Maybe a }
    deriving Typeable


-- | A function to verify user credentials
type CheckCreds = ByteString
                  -> ByteString
                  -> IO Bool


-- | Retrieve the 'AuthId' using Authorization header.
--
-- If valid credentials are found and authorized the
-- auth id is cached.
--
-- TODO use more general type than Text to represent
-- the auth id
defaultMaybeBasicAuthId
  :: (MonadIO m, MonadThrow m, MonadBaseControl IO m)
     => CheckCreds
     -> AuthSettings
     -> HandlerT site m (Maybe Text)
defaultMaybeBasicAuthId auth cfg =
    cachedAuth $ waiRequest >>= maybeBasicAuthId auth cfg


-- | Cached Authentication credentials
cachedAuth
  :: (MonadIO m, MonadThrow m, MonadBaseControl IO m)
     => HandlerT site m (Maybe Text)
     -> HandlerT site m (Maybe Text)
cachedAuth = fmap unCached . cached . fmap CachedBasicAuthId


-- | Use the HTTP Basic _Authorization_ header to retrieve
-- the AuthId of request
--
-- This function uses yesod 'cachedAuth' to cache the result of
-- the first succesful header lookup.
--
-- Subsequent calls to 'maybeAuthId' do not require the 'CheckCreds'
-- function to be run again.
maybeBasicAuthId
  :: MonadIO m
     => CheckCreds
     -> AuthSettings
     -> Request
     -> m (Maybe Text)
maybeBasicAuthId checkCreds AuthSettings{..} req =
    case authorization of
      Just (strategy, userpass)
        | BS.map toLower strategy == "basic" ->
              authorizeCredentials $ BS.dropWhile isSpace userpass
        | otherwise -> return Nothing
      _ -> return Nothing
  where
    authorization = BS.break isSpace
                    <$> lookup "Authorization" (requestHeaders req)
    authorizeCredentials encoded =
      let (username, password') = BS.breakByte _colon $ decodeLenient encoded
      in case BS.uncons password' of
          Nothing -> return Nothing
          Just (_,password) -> do
            authorized <- liftIO $ checkCreds username password
            return $ if authorized
                       then Just $ T.decodeUtf8 username
                       else Nothing
