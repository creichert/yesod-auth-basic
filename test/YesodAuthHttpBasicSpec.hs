
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}

module YesodAuthHttpBasicSpec where

import           Control.Monad (forM_)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import           Data.IORef
import           Test.Hspec
import           Yesod       hiding (get)
import           Yesod.Auth.Http.Basic
import           Yesod.Test


spec :: SpecWith ()
spec = describe "Yesod HTTP Basic Authentication" $ do
  calls <- runIO $ newIORef 0
  yesodSpec (app calls) $ do
    forM_ validHeaders $ \(label, header, username) ->
      yit label $ do
        liftIO $ writeIORef calls 0
        requestWith $ Just header
        statusIs 200
        bodyEquals username
        -- The handler asks twice, but the checker runs only once per request.
        liftIO $ readIORef calls `shouldReturn` 1

    forM_ malformedHeaders $ \(label, header) ->
      yit ("rejects " <> label <> " before checking credentials") $ do
        liftIO $ writeIORef calls 0
        requestWith $ Just header
        statusIs 401
        liftIO $ readIORef calls `shouldReturn` 0

    yit "rejects missing Authorization without checking credentials" $ do
      liftIO $ writeIORef calls 0
      requestWith Nothing
      statusIs 401
      liftIO $ readIORef calls `shouldReturn` 0

    yit "caches a failed credential check within the request" $ do
      liftIO $ writeIORef calls 0
      requestWith $ Just $ basic "user:wrong"
      statusIs 401
      liftIO $ readIORef calls `shouldReturn` 1

    yit "does not reuse authentication between HTTP requests" $ do
      liftIO $ writeIORef calls 0
      requestWith $ Just $ basic "user:secret"
      statusIs 200
      requestWith $ Just $ basic "user:secret"
      statusIs 200
      liftIO $ readIORef calls `shouldReturn` 2

validHeaders :: [(String, ByteString, String)]
validHeaders =
  [ ("accepts standard Basic Auth", basic "user:secret", "user")
  , ("accepts a case-insensitive scheme", "bAsIc " <> payload, "user")
  , ("accepts multiple ASCII separator spaces", "Basic   " <> payload, "user")
  , ("preserves colons in the password and accepts Base64 needing no padding", basic "user:se:cret", "user")
  , ("preserves whitespace inside decoded credentials", basic " user : secret ", " user ")
  , ("allows the checker to accept an empty password", basic "user:", "user")
  ]

malformedHeaders :: [(String, ByteString)]
malformedHeaders =
  [ ("double-quoted tokens", "Basic \"" <> payload <> "\"")
  , ("single-quoted tokens", "Basic '" <> payload <> "'")
  , ("punctuation inside Base64", "Basic " <> BS.take 4 payload <> "!" <> BS.drop 4 payload)
  , ("whitespace inside Base64", "Basic " <> BS.take 4 payload <> " " <> BS.drop 4 payload)
  , ("a tab separator", "Basic\t" <> payload)
  , ("a tab after a separator space", "Basic \t" <> payload)
  , ("a nonbreaking-space separator", "Basic\160" <> payload)
  , ("missing required padding", "Basic " <> BS.takeWhile (/= 61) payload)
  , ("excess padding", "Basic " <> payload <> "=")
  , ("trailing junk after padding", "Basic " <> payload <> "ignored")
  , ("a trailing quote after padding", "Basic " <> payload <> "\"")
  , ("an impossible Base64 length", basic "user:se:cret" <> "A")
  , ("credentials without a colon", basic "user")
  , ("an unsupported scheme", "Bearer " <> payload)
  , ("a missing separator", "Basic" <> payload)
  , ("an empty payload", "Basic ")
  ]

payload :: ByteString
payload = Base64.encode "user:secret"

basic :: ByteString -> ByteString
basic credentials = "Basic " <> Base64.encode credentials

requestWith :: Maybe ByteString -> YesodExample LiteApp ()
requestWith header = request $ do
  setMethod "GET"
  setUrl $ LiteAppRoute []
  forM_ header $ \value -> addRequestHeader ("Authorization", value)


instance RenderMessage LiteApp FormMessage where
  renderMessage _ _ = defaultFormMessage


app :: IORef Int -> LiteApp
app calls = liteApp $
  dispatchTo $ do
    first <- defaultMaybeBasicAuthId checkCreds defaultAuthSettings
    second <- defaultMaybeBasicAuthId checkCreds defaultAuthSettings
    case (first, second) of
      (Just username, Just cachedUsername) | username == cachedUsername -> return username
      _ -> notAuthenticated
  where
    checkCreds username password = do
      modifyIORef calls (+ 1)
      return $ (username, password) `elem`
        [("user", "secret"), ("user", "se:cret"), (" user ", " secret "), ("user", "")]
