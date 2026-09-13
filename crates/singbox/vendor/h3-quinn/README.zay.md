# h3 fork test support

The two source files in this directory are an unmodified copy of
`h3-quinn` 0.0.10. The published `h3` 0.0.8 crate keeps its internal tests
pointing at `../../../h3-quinn/src/lib.rs`, but does not package that sibling.
They are present only so the vendored h3 header regressions can be compiled
and run; production dependency resolution continues to use the normal
`h3-quinn` crate.
