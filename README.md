# Access Token Provider [![Hackage version](https://img.shields.io/hackage/v/access-token-provider.svg?label=Hackage)](https://hackage.haskell.org/package/access-token-provider) [![Stackage version](https://www.stackage.org/package/access-token-provider/badge/lts?label=Stackage)](https://www.stackage.org/package/access-token-provider) [![Build Status](https://travis-ci.org/mtesseract/access-token-provider.svg?branch=master)](https://travis-ci.org/mtesseract/access-token-provider)

This package provides a convenient retrieval mechanism for access
tokens. Multiple provider backends, including OAuth2 Resource Owner
Password Credentials Grant, file-based token access (e.g. for
Kubernetes) and fetching tokens from the environment (e.g. for local
testing) are supported; custom provider backends can easily be added.

## Examples

```haskell
import qualified Security.AccessTokenProvider as ATP

retrieveSomeToken :: IO ()
retrieveSomeToken = do
  tokenProvider <- ATP.new (AccessTokenName "token-name")
  token <- ATP.retrieveAccessToken tokenProvider
  print token
```

## Configuration

Configuration is done by setting certain environment variables,
depending on the provider.

### OAuth2 based token retrieval

The OAuth2 (Resource Owner Password Credentials Grant) provider
expects the `ATP_CONF_ROPCG` environment variable to contain a JSON
object as follows:

```json
{
  "credentials_directory": "/optional/credentials/directory",
  "auth_endpoint": "<OAuth2 authentication endpoint>",
  "tokens": {"token-name": {"scopes": ["first-scope", "second-scope"]}}
}
```

The `credentials_directory` setting defaults to the content of the
environment variable `CREDENTIALS_DIR`. It is expected to contain the
files `user.json` and `client.json`, containing the user and client
credentials respectively.

### File based token retrieval (e.g. for Kubernetes)

The file based provider expects the `ATP_CONF_FILE` environment
variable to contain a JSON object as follows:

```json
{
  "tokens": {"token-name": "/some/file/name"}
}
```

As a short cut, you can simply save a token path directly in the
environment variable `TOKEN_FILE`.

### Environment based token retrieval (e.g. for testing)

The file based provider expects the `ATP_CONF_FIXED` environment
variable to contain a JSON object as follows:

```json
{
  "tokens": {"token-name": "some-fixed-token"}
}
```
