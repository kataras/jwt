module github.com/kataras/jwt/_examples

go 1.26

// The examples are their own module so that a sample needing a YAML parser, or any other
// dependency, cannot put one into the library's go.mod. The library has none and keeps
// none. Before this file existed, _examples/multiple-kids imported gopkg.in/yaml.v3,
// resolved against the parent module, and simply did not build.
replace github.com/kataras/jwt => ../

require (
	github.com/kataras/jwt v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)
