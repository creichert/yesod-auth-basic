
module Main (main) where

import           Language.Haskell.HLint (hlint)
import           System.Exit            (exitFailure, exitSuccess)


main :: IO ()
main = do
    hints <- hlint arguments
    print hints
    if null hints
       then exitSuccess
       else exitFailure
  where
    arguments = [
                  "Yesod"
                , "test"
                ]
