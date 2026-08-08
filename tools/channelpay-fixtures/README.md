# Official ChannelPay golden-vector generator

This command produces the binary fixtures consumed by the isolated Rust
compatibility tests. The bytes come from the official Hacash Go serializers,
not from the wallet's Rust implementation.

Pinned inputs:

- `github.com/hacash/channelpay` at
  `d63e4109f2f9f4471f0838536b68b240848a77ef`
- `github.com/hacash/core` at
  `8bb265fc1a68acc0af3236354fba7386bac4d9c5`

The upstream repositories use the legacy GOPATH layout. Reproduction therefore
requires those exact revisions under:

```text
$GOPATH/src/github.com/hacash/channelpay
$GOPATH/src/github.com/hacash/core
```

The pinned ChannelPay protocol package also imports the official `node`,
`x16rs`, and `jsonparser` repositories. Build in a disposable GOPATH and do not
replace any serializer with wallet code. The HDNS source needs CGO; fixtures do
not use HDNS, so a fixture-only GOPATH may exclude `protocol/hdns.go`.

Run:

```text
GO111MODULE=off go run tools/channelpay-fixtures/generate.go \
  crates/wallet-core/tests/fixtures/official-channelpay-v1
```

After generation, review the manifest and update the manifest SHA-256 pinned in
the Rust integration test. A changed digest is a compatibility review event,
not an automatic update.
