# ADR-008: Configuration

## Status

Accepted

## Context

The application needs configuration for various environments (development, staging, production) with different storage backends, logging levels, and security settings.

## Decision

Configuration is managed through:

1. **YAML files** for structured configuration
2. **Environment variables** for overrides (12-factor app)
3. **Validation** at startup
4. **Defaults** for development convenience

Priority (highest to lowest):
1. Environment variables
2. YAML configuration file
3. Default values

Environment variable naming: `WALLET_<SECTION>_<KEY>`

## Rationale

- YAML provides readable, structured configuration
- Environment variables support containerized deployments
- Validation catches misconfigurations early
- Defaults enable quick development setup
- Follows 12-factor app principles

## Consequences

- All configuration options documented
- Sensitive values (secrets) only via environment variables
- Configuration validated at startup
- Tests can override configuration easily
