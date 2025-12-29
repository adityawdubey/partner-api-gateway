# Production Hardening 

## Authentication
- Short-lived access tokens with exp/iat enforced; add refresh tokens plus revocation/versioning (jti or token_version) to invalidate early.
- Rotate the JWT signing key on a schedule; record key IDs (kid) so old tokens can be verified during rollout.
- For browser/SPAs: support HttpOnly/SameSite/Secure cookies; for third parties: OAuth2/OIDC flows.

## API Keys
- Keep hashing; add expires_at and revoked flags, plus last_used and status history.
- Enforce expiry/revocation before issuing JWTs; support key rotation/rollover without downtime.

## Rate Limiting
- Move limiter to Redis for multi-instance deployments; use token bucket/sliding window with burst + sustained limits.
- Support per-endpoint/prefix overrides; always return Retry-After and rate headers.

## Persistence
- Replace SQLite with PostgreSQL/MySQL; add Alembic migrations and connection pooling.
- Backups/restore plans; consider TTL/partitioning for hot tables (rate limits, audit logs).

## Edge / Networking
- Front with Nginx/HAProxy/ALB for TLS termination, compression, buffering, slow-client protection, and load balancing across gunicorn/uvicorn workers.
- Tune proxy/read/connect timeouts to match backend SLAs.

## Observability
- Emit structured JSON logs with request IDs/correlation IDs.
- Add metrics (latency, rate-limit hits/misses, upstream errors) and traces (OpenTelemetry); ship to centralized stack (ELK/Datadog/Prometheus/Grafana).

## Security Headers & CORS
- HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy; add CSP if serving UI.
- Lock CORS to allowed origins; default-deny.

## Input/Output Hardening
- Enforce max body size and strict timeouts.
- Prevent SSRF by restricting upstream hosts; optionally validate payload schemas on ingress/egress.

## Secrets & Config
- Load secrets from env/secret manager (not repo); rotate regularly and on incident.

## Lifecycle & Ops
- Add readiness/liveness probes, graceful shutdown.
- Background cleanup/TTL for rate-limit and audit rows; runbooks for key rotation and token revocation.

## Auditing & Compliance
- Keep audit logs; add PII redaction, retention policies, and admin access. Consider append-only/immutable storage for compliance.

## Testing & CI/CD
- Add unit/integration tests, contract tests with a mock of JSONPlaceholder, lint/format, CI pipeline, and deploy pipeline with migrations + health checks (canary/blue-green if possible).

## Performance & Resilience
- Use httpx connection pooling/keep-alive, tuned retries, and circuit breakers/fallbacks for upstream failures.
- Add caching (Redis/HTTP cache) for cacheable GETs with ETag/If-None-Match.