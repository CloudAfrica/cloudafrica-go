# cloudafrica-go

Go SDK for the CloudAfrica public API.

```go
import "github.com/CloudAfrica/cloudafrica-go"

c, err := cloudafrica.New("https://api.cloudafrica.net", cloudafrica.StaticToken(os.Getenv("CLOUDAFRICA_TOKEN")))
if err != nil {
	return err
}
resp, err := c.API.ListVmsWithResponse(ctx, nil)
if err != nil {
	return err
}
if err := cloudafrica.CheckResponse(resp.HTTPResponse, resp.Body); err != nil {
	return err // *cloudafrica.APIError
}
```

`c.API` holds the generated calls, one per operation in [`openapi.json`](openapi.json). Every call goes through a
transport that:

- takes its bearer token from the `TokenSource` on every attempt (`StaticToken` for a `cak_` token, or your own
  refreshing source);
- sends one `Idempotency-Key` per write, reused across that write's retries;
- retries 429 (waiting for `X-RateLimit-Reset`), 503, `idempotency-in-progress` and `resource-not-ready`;
- caps in-flight requests (`WithConcurrency`, default 4).

`WaitForOperation` polls an asynchronous operation (the `Location` of a 202) until it completes or fails.

## Regenerating

`openapi.json` is pinned; `openapi.source` records where it came from.

```sh
make regen                                    # fetch from production and regenerate
make regen OPENAPI_FILE=path/to/gateway.json  # or from a local nebula gateway build
make generate                                 # regenerate from the pinned document only
```

`regen` refuses a document that lists any server other than production. CI fails when `client.gen.go` differs
from a fresh generation.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
