# go-ipset #

This library is a simple GoLang wrapper to the IPtables ipset userspace utility.
It provides an interface to allow Go programs to easily manipulate ipsets.
It is currently limited to sets of `type hash`.

For ipset command documentation: http://ipset.netfilter.org/ipset.man.html

go-ipset requires ipset kernel module and userspace utility version 6.0 or greater.

## Installation ##

Install go-ipset using the "go get" command:

    go get github.com/zigmund/go-ipset

## API Reference ##

[![Go Reference](https://pkg.go.dev/badge/github.com/zigmund/go-ipset/ipset.svg)](https://pkg.go.dev/github.com/zigmund/go-ipset/ipset)

## Usage ##

```go
import "github.com/zigmund/go-ipset/ipset"
```

#### Create a new set

Construct a new IPset instance (creating the set on the fly), then use the various methods to manipulate the IPset.
For example, to create a new ipset "customers" of type `hash:ip` for storing plain IPv4 addresses:

```go
customers := ipset.New("customers", "hash:ip", &ipset.Params{})
```

To create a new ipset to store different sized IPv4 network addresses (with /mask).

```go
trustedNetworks := ipset.New("trusted-networks", "hash:net", &ipset.Params{})
```

#### Add a single entry to the set

```go
customers.Add("8.8.2.2")
```

#### Populate the set with IPv4 addresses (overwriting the previous content)

```go
ips := []string{"8.8.8.8", "8.8.4.4"}
customers.Refresh(ips)
```

#### Remove a single entry from that set:

```go
customers.Del("8.8.8.8")
```

#### Configure advanced set options

You can configure advanced options when creating a new set by supplying the parameters in the `ipset.Params` struct.

```go
type Params struct {
  HashFamily       string
  HashSize         int
  MaxElem          int
  Timeout          int
  RecreateOnChange bool
}
```
See http://ipset.netfilter.org/ipset.man.html for their meaning.

For example, to create a set whose entries will expire after 60 seconds, lets say for temporarily limiting abusive clients:

```go
abusers := ipset.New("ratelimited", "hash:ip", &ipset.Params{Timeout: 60})
```

#### List entries of a set
```go
// list is []string
list ipset.List("customers")
```

#### Change parameters of an existing set

Kernel does not allow to change `maxelem` and `timeout` of an existing set, so `New` fails on such set.
With `RecreateOnChange` the existing set is hot swapped with a new empty set with the specified parameters.
iptables rules referencing the set are kept, but all entries are lost.

```go
abusers := ipset.New("ratelimited", "hash:ip", &ipset.Params{MaxElem: 262144, Timeout: 60, RecreateOnChange: true})
```

#### Show set properties without entries

```go
// header is *ipset.Header with HashSize, MaxElem, Timeout, Entries, etc.
header, err := abusers.Header()
// or by set name
header, err = ipset.ListHeader("ratelimited")
```

## Testing ##

Integration tests require root and ipset utility, otherwise they are skipped:

    sudo go test ./...
