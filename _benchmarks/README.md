# Benchmarks

## System

|    |    |
|----|:---|
| Processor | Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz |
| RAM | 15.85 GB |
| OS | Microsoft Windows 10 Pro for Workstations |

<br/>

**Run the benchmarks**

```sh
$ go test -bench=.
# OR powershell:
# go test -benchmem -run=^$ benchmarks -bench .
```

## Results

Comparison between: [kataras/jwt](https://github.com/kataras/jwt), [dgrijalva/jwt-go](github.com/dgrijalva/jwt-go) and [go-jose/go-jose](https://github.com/go-jose/go-jose). Higher is better.

![Benchmarks Total Repetitions - higher is better](http://iris-go.com/images/jwt/benchmarks.png)

### Sign

```sh
BenchmarkSign_Map                      324322              3534 ns/op            1904 B/op         30 allocs/op
BenchmarkSign_Struct                   446637              2653 ns/op            1344 B/op         21 allocs/op

BenchmarkSign_jwt_go_Map               233316              5161 ns/op            3057 B/op         50 allocs/op
BenchmarkSign_jwt_go_Struct            299694              3994 ns/op            2289 B/op         35 allocs/op
BenchmarkSign_jwt_go_Struct2           307395              3855 ns/op            2209 B/op         35 allocs/op

BenchmarkSign_go_jose_Map              151389              7927 ns/op            5299 B/op         85 allocs/op
BenchmarkSign_go_jose_Struct           109213             10932 ns/op            6692 B/op        108 allocs/op
```

### Verify

```sh
BenchmarkVerify                        363290              3334 ns/op            1536 B/op         22 allocs/op

BenchmarkVerify_jwt_go                 176756              6819 ns/op            3656 B/op         66 allocs/op
BenchmarkVerify_go_jose                122252              9902 ns/op            6104 B/op         85 allocs/op
```
