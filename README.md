# Access Token Provider

This package provides a convenient retrieval mechanism of access
tokens. Access Token Provider supporting multiple provider backends,
including OAuth2 Resource Owner Password Credentials Grant, file-based
token access (e.g. for Kubernetes) and fetching tokens from the
environment (e.g. for local testing). The package is configurable via
environment variables. It uses Katip for logging.

## Examples

```haskell
import qualified Security.AccessTokenProvider as ATP

retrieveSomeToken :: KatipContextT IO ()
retrieveSomeToken = do
  tokenProvider <- ATP.new (AccessTokenName "token-name")
  token <- retrieveAccessToken tokenProvider
  liftIO $ print token
```

## Configuration

Configuration is done by setting the environment variable `ATP_CONF`.

### OAuth2 based token retrieval

For OAuth2 (Resource Owner Password Credentials Grant) provider, use:

```json
{
  "provider": "ropcg",
  "credentials_directory": "/optional/credentials/directory",
  "auth_endpoint": "<OAuth2 authentication endpoint>",
  "tokens": {"label1": {"scopes": ["first-scope", "second-scope"]}}
}
```

The `credentials_directory` setting defaults to the content of the
environment variable `CREDENTIALS_DIR`. It is expected to contain the
files `user.json` and `client.json`, containing the user and client
credentials respectively.

### File based token retrieval (e.g. for Kubernetes)

```json
{
  "provider": "file",
  "tokens": {"label1": "/some/file/name"}
}
```

As a short cut, you can simply save a token path directly in the
environment variable `TOKEN_FILE`.

### Environment based token retrieval (e.g. for testing)

```json
{
  "provider": "fixed",
  "tokens": {"label1": "some-fixed-token"}
}
```

As a short cut, you can simply save a token directly in the
environment variable `TOKEN`.
