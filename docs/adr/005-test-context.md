# ADR-005: Testing Context

## Status

Accepted

## Context

Go tests often need a `context.Context` for operations that support cancellation and timeouts.

## Decision

We use `t.Context()` (Go 1.21+) or create a test context in tests.

```go
func TestSomething(t *testing.T) {
    ctx := t.Context()
    // or for older Go versions:
    // ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    // defer cancel()
    
    result, err := SomeOperation(ctx)
    // ...
}
```

## Rationale

- Simple to handle the Context within the test
- The context is canceled just before Cleanup-registered functions are called
- Ensures proper resource cleanup
- Consistent across all tests

## Consequences

- All tests using context should use this pattern
- Long-running operations should respect context cancellation
- Test timeouts are automatically managed
