# ADR-007: Error Handling

## Status

Accepted

## Context

Consistent error handling is essential for debugging, logging, and user experience.

## Decision

1. **Sentinel errors** for common cases:
   ```go
   var (
       ErrNotFound      = errors.New("not found")
       ErrAlreadyExists = errors.New("already exists")
       ErrUnauthorized  = errors.New("unauthorized")
   )
   ```

2. **Error wrapping** for context:
   ```go
   return fmt.Errorf("failed to create user: %w", err)
   ```

3. **Error checking** with `errors.Is`:
   ```go
   if errors.Is(err, storage.ErrNotFound) {
       return nil, ErrUserNotFound
   }
   ```

4. **API errors** with consistent format:
   ```go
   c.JSON(400, gin.H{"error": err.Error()})
   ```

## Rationale

- Consistent error handling improves debugging
- Error wrapping preserves the error chain
- Sentinel errors enable type-safe error checking
- Consistent API responses improve client experience

## Consequences

- All errors should be wrapped with context
- API layer translates internal errors to HTTP responses
- Logs include full error chains
- Tests verify error conditions
