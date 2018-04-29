module Security.AccessTokenProvider.Internal.Types.Severity where

data Severity
  = Debug
  | Info
  | Warning
  | Error
  | Alert
  deriving (Eq, Ord, Enum, Show)
