# Benchmarks

Comparison between [kataras/jwt](https://github.com/kataras/jwt),
[golang-jwt/jwt](https://github.com/golang-jwt/jwt) and
[go-jose/go-jose](https://github.com/go-jose/go-jose), signing and verifying the same
HS256 token.

This is a separate Go module. The comparison libraries are its dependencies and never reach
the library's own `go.mod`, which has none.

## Results

![Time per operation, lower is better](benchmarks.svg)

![Allocations per operation, lower is better](benchmarks-allocations.svg)

![Memory per operation, lower is better](benchmarks-memory.svg)

Allocations are the number to watch. They are the stable signal between runs, while the
timings move with whatever else the machine is doing, and they are what the library's
release checks are written against.

### System

|    |    |
|----|:---|
| Processor | Snapdragon(R) X 12-core X1E80100 @ 3.40 GHz |
| RAM | 15.61 GB |
| OS | Microsoft Windows 11 Home, ARM 64-bit |
| Go | go1.26.5 windows/arm64 |

### Sign

```sh
BenchmarkSign_Map-12                      424600       2777 ns/op       1528 B/op       23 allocs/op
BenchmarkSign_Struct-12                   550389       2521 ns/op       1392 B/op       21 allocs/op

BenchmarkSign_jwt_go_Map-12               393931       3790 ns/op       2377 B/op       37 allocs/op
BenchmarkSign_jwt_go_Struct-12            269436       4000 ns/op       1913 B/op       27 allocs/op
BenchmarkSign_jwt_go_Struct2-12           444030       3435 ns/op       1833 B/op       27 allocs/op

BenchmarkSign_go_jose_Map-12              171348       6884 ns/op       4584 B/op       72 allocs/op
BenchmarkSign_go_jose_Struct-12           141780      10237 ns/op       5944 B/op       93 allocs/op
```

### Verify

```sh
BenchmarkVerify-12                        352230       3048 ns/op       1376 B/op       18 allocs/op

BenchmarkVerify_jwt_go-12                 272935       5799 ns/op       3088 B/op       51 allocs/op
BenchmarkVerify_go_jose-12                144706       9464 ns/op       5896 B/op       83 allocs/op
```

## Running them

```sh
go test -bench=. -benchmem -run=XXX
```

## Redrawing the charts

`chart/` reads `go test -bench` output and writes the three SVG files above. It uses only
the standard library, so it adds nothing to this module's dependencies, and it emits a
plain SVG document rather than calling a chart library, so the output is deterministic and
renders anywhere an `<img>` does. A `prefers-color-scheme` block adapts it to light and
dark pages.

```sh
go run ./chart                                  # run the benchmarks, then draw
go run ./chart -in bench.txt                    # draw from a run you already have
go run ./chart -note "Ryzen 9 7950X, 16 cores"  # add the CPU, which go test omits on arm64
```

Regenerate after any change that could move the numbers, and update the tables above from
the same run, so the charts and the text cannot disagree.
