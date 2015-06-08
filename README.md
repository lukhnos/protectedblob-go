protectedblob
=============

[![Build Status](https://travis-ci.org/lukhnos/protectedblob-go.svg?branch=master)](https://travis-ci.org/lukhnos/protectedblob-go)

Package protectedblob can create passphrase-protected wrappers for binary
blobs (any non-empty arbitary byte arrays).

The wrapper, called an envelop, uses a randomly-generated key to encrypt the
given byte array. The key is then encrypted with another key that's derived
from user-supplied passphrase. The integrity of the encrypted blob is checked
with an HMAC (hash-based message authentication code). The HMAC is computed
with the encrypted data and another key derived from the passphrase. Together,
this implements an encrypt-then-MAC authenticated encryption scheme.

```go
package main

import "lukhnos.org/protectedblob"

func someFunc() {
    envelope, _ := protectedblob.Create(plaintext, passphrase, rounds)
    jsonBytes, _ := envelope.ToJSON()
    // Write out the JSON.

    envelope, _ := protectedblob.FromJSON(jsonBytes)
    plaintext, _ := envelope.GetPlaintext(passphrase)
}
```

A command line tool under the same name is also provided to create and use
the envelopes. To install the command line tool:

    go get lukhnos.org/protectedblob/cmd/protectedblob

This is a Go port of [protectedblob-py](https://github.com/lukhnos/protectedblob-py).
