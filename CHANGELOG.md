# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased] - 2025-01-20

### Fixed
- Fixed deterministic behavior in `NonExistentPath` test case for SMT verification. When no branch exists at a position (`branch == nil` in `generatePath`), a `MerkleTreeStep` with `Branch=nil` is now created rather than `Branch=[]` to properly indicate "no branch exists". During verification, nil branches do not update `currentPath`, while empty array branches do.

---

## [Unreleased] - 2025-07-20

### Fixed
- Fixed `MerkleTreePath.Verify()` implementation to be compatible with TypeScript's `verify()` from the commons library:
  - Fixed variable shadowing bug where `bytes` variable was incorrectly scoped
  - Fixed branch initialization to properly distinguish between null and empty branches
  - Fixed hash calculation for empty branches to use `path + currentHash` instead of just `[0]`
  - Fixed branch value decoding — values are hex-encoded, not imprint hex
  - Path reconstruction now correctly preserves all bits of the `requestId`
  - Verification now passes for complex 273-bit paths matching TypeScript behavior

---

## [Unreleased] - 2025-07-06

### Fixed
- **Block finalization race condition**: Blocks were exposed via API before all commitment data was stored. `FinalizeBlock` now stores aggregator records and marks commitments as processed _before_ storing the block, ensuring blocks are only visible once fully finalized.
- **Performance test commitment counting**: Fixed sequential block checking to handle gaps from repeat UCs; added `REQUEST_ID_EXISTS` handling to track IDs; fixed critical bug where `requestID` was calculated with a different state hash than the authenticator.

### Changed
- Performance test now checks all blocks from start to latest, handling gaps without early termination.

---

## [Unreleased] - 2025-07-06 (morning)

### Added
- **BFT Core improvements** (`internal/bft/client.go`):
  - Proper repeat UC detection using `InputRecord` comparison via `isRepeatUC` method
  - Sequential UC processing with `ucProcessingMutex` to prevent race conditions during round transitions
  - `lastRootRound` tracking to monitor root chain rounds with enhanced logging
  - Configurable round duration via `ROUND_DURATION` environment variable (default: 1 second)

---

## [Unreleased] - 2025-07-05

### Added
- **Asynchronous logging**: `AsyncLogger` wrapper implementing `slog.Handler` with channel-based buffering, background worker with 10 ms periodic flush, and graceful shutdown. Configurable via `LOG_ENABLE_ASYNC` (default `true`) and `LOG_ASYNC_BUFFER_SIZE` (default `10000`).

### Fixed
- **Root chain synchronization**: `CertificationRequest` now always uses `nextExpectedRound` from the root chain when available, with fallback inference from last UC at startup.
- **UC mismatch handling**: Fixed inverted logic for "root chain behind" scenario; properly clears proposed block and starts new round to resync.
- **Sequential round processing**: UC handlers no longer start new rounds immediately, preventing race conditions. Block numbers automatically adjust to match root chain expectations.
- **Deferred commitment finalization**: Commitments are no longer lost when rounds are skipped. Commitments stay unprocessed until the block is finalized with a UC; aggregator records are stored with the correct finalized block number.
- **Performance test metrics**: Test now waits for all commitments to be processed before calculating statistics, tracking only commitments submitted by the current run via `sync.Map`.

### Changed
- Reduced batch limit from 10,000 to 1,000 for sub-second round processing.

---

## [Unreleased] - 2025-07-05 (analysis)

### Documentation
- Analyzed BFT core `partition/node.go` to document repeat UC detection, T1 timeout mechanism, and sequential processing patterns as a roadmap for aggregator improvements.

---

## [Unreleased] - 2025-07-05 (logging)

### Added
- Comprehensive round manager logging: `StartNewRound`, `processCurrentRound`, `proposeBlock`, `FinalizeBlock`, and BFT client methods now emit detailed structured logs for diagnosing block production issues.

---

## [Unreleased] - 2025-07-05 (performance)

### Added
- Performance test enhancement: test now waits for all commitments to be processed with a 30-second timeout, real-time progress updates, and accurate end-to-end throughput metrics.

---

## [Unreleased] - 2025-06-09 (docs)

### Added
- Interactive and executable JSON-RPC API documentation at `/docs` endpoint with live testing, cURL export, keyboard shortcuts (`Ctrl+Enter`), response timing, and reset functionality.

---

## [Unreleased] - 2025-06-09 (docker)

### Added
- `docker-compose.yml` with MongoDB and Aggregator services, persistent volumes, and health checks.
- Multi-stage `Dockerfile` for optimized Go binary builds on Alpine.
- `scripts/mongo-init.js` for automated collection and index creation.
- Makefile targets: `docker-build`, `docker-up`, `docker-down`, `docker-logs`, `docker-restart`, `docker-rebuild`, `docker-clean`.

---

## [Unreleased] - 2025-06-09 (go-version)

### Changed
- Updated Go version requirement from 1.22 to 1.24 in `go.mod` and `README.md`.

---

## [Unreleased] - 2025-06-09 (foundation)

### Added
- Complete Go project structure with standard layout (`cmd/`, `internal/`, `pkg/`).
- Configuration management via environment variables with validation and defaults.
- Core data models with JSON serialization for `BigInt`, `HexBytes`, and `Timestamp` types.
- MongoDB storage layer with interface-based abstraction and full implementations (commitments, aggregator_records, blocks, smt_nodes, block_records, leadership collections).
- JSON-RPC 2.0 server with middleware support, concurrency limiting, and structured error codes.
- HTTP gateway server using Gin with health endpoint (`/health`) and API documentation (`/docs`).
- Business logic service implementing all aggregator methods: `submit_commitment`, `get_inclusion_proof`, `get_no_deletion_proof`, `get_block_height`, `get_block`, `get_block_commitments`.
- MongoDB-based leader election infrastructure for high availability.
- Graceful shutdown, TLS support, CORS headers, request correlation with UUIDs, and structured logging via Logrus.
