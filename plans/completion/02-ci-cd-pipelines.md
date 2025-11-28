# CI/CD Pipeline Configuration

Complete CI/CD setup for LLM-Data-Vault including GitHub Actions workflows, pre-commit hooks, security scanning, and release automation.

## 1. GitHub Actions Workflows

### 1.1 Main CI Pipeline (.github/workflows/ci.yml)

```yaml
name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  check:
    name: Check
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Run cargo check
        run: cargo check --all-features --workspace

  fmt:
    name: Format
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt

      - name: Check code formatting
        run: cargo fmt --all -- --check

  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    permissions:
      checks: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Run clippy
        run: cargo clippy --all-features --workspace -- -D warnings

      - name: Run clippy (tests)
        run: cargo clippy --all-features --workspace --tests -- -D warnings

  test:
    name: Test
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, beta]
        exclude:
          - os: macos-latest
            rust: beta
          - os: windows-latest
            rust: beta
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Run tests
        run: cargo test --all-features --workspace

      - name: Run tests (release mode)
        run: cargo test --all-features --workspace --release

  coverage:
    name: Code Coverage
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-tarpaulin
        run: cargo install cargo-tarpaulin

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Generate coverage
        run: cargo tarpaulin --all-features --workspace --timeout 300 --out xml

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: ./cobertura.xml
          fail_ci_if_error: true
          token: ${{ secrets.CODECOV_TOKEN }}

  docs:
    name: Documentation
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Build documentation
        run: cargo doc --all-features --workspace --no-deps
        env:
          RUSTDOCFLAGS: -D warnings

      - name: Upload documentation
        uses: actions/upload-artifact@v4
        with:
          name: documentation
          path: target/doc/

  audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Run security audit
        run: cargo audit --deny warnings

  msrv:
    name: Minimum Supported Rust Version
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain (MSRV)
        uses: dtolnay/rust-toolchain@master
        with:
          toolchain: 1.75.0

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Check MSRV
        run: cargo check --all-features --workspace
```

### 1.2 Release Pipeline (.github/workflows/release.yml)

```yaml
name: Release

on:
  push:
    tags:
      - 'v[0-9]+.[0-9]+.[0-9]+'

permissions:
  contents: write

env:
  CARGO_TERM_COLOR: always

jobs:
  create-release:
    name: Create Release
    runs-on: ubuntu-latest
    outputs:
      upload_url: ${{ steps.create_release.outputs.upload_url }}
      version: ${{ steps.get_version.outputs.version }}
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get version from tag
        id: get_version
        run: echo "version=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT

      - name: Generate changelog
        id: changelog
        uses: metcalfc/changelog-generator@v4.3.1
        with:
          myToken: ${{ secrets.GITHUB_TOKEN }}

      - name: Create release
        id: create_release
        uses: actions/create-release@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          tag_name: ${{ github.ref }}
          release_name: Release v${{ steps.get_version.outputs.version }}
          body: ${{ steps.changelog.outputs.changelog }}
          draft: false
          prerelease: false

  build-binaries:
    name: Build Binary (${{ matrix.target }})
    needs: create-release
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            binary_name: llm-data-vault
            asset_name: llm-data-vault-linux-amd64
          - os: ubuntu-latest
            target: x86_64-unknown-linux-musl
            binary_name: llm-data-vault
            asset_name: llm-data-vault-linux-musl-amd64
          - os: macos-latest
            target: x86_64-apple-darwin
            binary_name: llm-data-vault
            asset_name: llm-data-vault-macos-amd64
          - os: macos-latest
            target: aarch64-apple-darwin
            binary_name: llm-data-vault
            asset_name: llm-data-vault-macos-arm64
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            binary_name: llm-data-vault.exe
            asset_name: llm-data-vault-windows-amd64.exe

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Install musl tools
        if: matrix.target == 'x86_64-unknown-linux-musl'
        run: sudo apt-get update && sudo apt-get install -y musl-tools

      - name: Build release binary
        run: cargo build --release --target ${{ matrix.target }}

      - name: Strip binary (Linux/macOS)
        if: matrix.os != 'windows-latest'
        run: strip target/${{ matrix.target }}/release/${{ matrix.binary_name }}

      - name: Create tarball (Linux/macOS)
        if: matrix.os != 'windows-latest'
        run: |
          cd target/${{ matrix.target }}/release
          tar czf ${{ matrix.asset_name }}.tar.gz ${{ matrix.binary_name }}
          mv ${{ matrix.asset_name }}.tar.gz ../../..

      - name: Create zip (Windows)
        if: matrix.os == 'windows-latest'
        run: |
          cd target/${{ matrix.target }}/release
          7z a ${{ matrix.asset_name }}.zip ${{ matrix.binary_name }}
          move ${{ matrix.asset_name }}.zip ../../..

      - name: Upload release asset (Linux/macOS)
        if: matrix.os != 'windows-latest'
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ needs.create-release.outputs.upload_url }}
          asset_path: ./${{ matrix.asset_name }}.tar.gz
          asset_name: ${{ matrix.asset_name }}.tar.gz
          asset_content_type: application/gzip

      - name: Upload release asset (Windows)
        if: matrix.os == 'windows-latest'
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ needs.create-release.outputs.upload_url }}
          asset_path: ./${{ matrix.asset_name }}.zip
          asset_name: ${{ matrix.asset_name }}.zip
          asset_content_type: application/zip

  build-docker:
    name: Build and Push Docker Image
    needs: create-release
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: |
            ${{ secrets.DOCKER_USERNAME }}/llm-data-vault
            ghcr.io/${{ github.repository }}
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
            type=sha

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

  publish-helm:
    name: Publish Helm Chart
    needs: create-release
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Helm
        uses: azure/setup-helm@v4
        with:
          version: 'v3.14.0'

      - name: Package Helm chart
        run: |
          helm package charts/llm-data-vault \
            --version ${{ needs.create-release.outputs.version }} \
            --app-version v${{ needs.create-release.outputs.version }}

      - name: Upload Helm chart to release
        uses: actions/upload-release-asset@v1
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          upload_url: ${{ needs.create-release.outputs.upload_url }}
          asset_path: ./llm-data-vault-${{ needs.create-release.outputs.version }}.tgz
          asset_name: llm-data-vault-${{ needs.create-release.outputs.version }}.tgz
          asset_content_type: application/gzip

  publish-crate:
    name: Publish to crates.io
    needs: create-release
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Publish to crates.io
        run: cargo publish --token ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

### 1.3 Security Scanning (.github/workflows/security.yml)

```yaml
name: Security

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    name: Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Run cargo audit
        run: cargo audit --json | tee audit-results.json

      - name: Upload audit results
        uses: actions/upload-artifact@v4
        with:
          name: audit-results
          path: audit-results.json

  sast:
    name: SAST Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: 'rust'

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build project
        run: cargo build --all-features --workspace

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3

  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/rust

  container-scan:
    name: Container Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t llm-data-vault:test .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'llm-data-vault:test'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

  sbom:
    name: Generate SBOM
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-sbom
        run: cargo install cargo-sbom

      - name: Generate SBOM
        run: cargo sbom > sbom.spdx.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json

  secrets-scan:
    name: Secrets Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 1.4 Performance Benchmarks (.github/workflows/benchmark.yml)

```yaml
name: Benchmarks

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  benchmark:
    name: Run Benchmarks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Run benchmarks
        run: cargo bench --workspace -- --output-format bencher | tee benchmark-results.txt

      - name: Download previous benchmark data
        uses: actions/cache@v4
        with:
          path: ./cache
          key: ${{ runner.os }}-benchmark

      - name: Store benchmark result
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'cargo'
          output-file-path: benchmark-results.txt
          github-token: ${{ secrets.GITHUB_TOKEN }}
          auto-push: true
          alert-threshold: '150%'
          comment-on-alert: true
          fail-on-alert: true

  criterion:
    name: Criterion Benchmarks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Setup Rust cache
        uses: Swatinem/rust-cache@v2
        with:
          cache-on-failure: true

      - name: Run Criterion benchmarks
        run: cargo bench --workspace --features criterion

      - name: Upload benchmark results
        uses: actions/upload-artifact@v4
        with:
          name: criterion-results
          path: target/criterion/
```

## 2. Pre-commit Hooks

### .pre-commit-config.yaml

```yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: check-yaml
      - id: check-toml
      - id: check-merge-conflict
      - id: check-case-conflict
      - id: check-added-large-files
        args: ['--maxkb=1000']
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: mixed-line-ending

  - repo: https://github.com/doublify/pre-commit-rust
    rev: v1.0
    hooks:
      - id: fmt
        name: cargo fmt
        description: Format Rust code with cargo fmt
        entry: cargo fmt
        language: system
        types: [rust]
        args: ['--', '--check']

      - id: clippy
        name: cargo clippy
        description: Run clippy lints
        entry: cargo clippy
        language: system
        types: [rust]
        args: ['--all-features', '--workspace', '--', '-D', 'warnings']
        pass_filenames: false

  - repo: local
    hooks:
      - id: cargo-test
        name: cargo test
        description: Run cargo tests
        entry: cargo test
        language: system
        types: [rust]
        args: ['--all-features', '--workspace']
        pass_filenames: false
        stages: [push]

      - id: cargo-audit
        name: cargo audit
        description: Check for security vulnerabilities
        entry: cargo audit
        language: system
        pass_filenames: false
        stages: [push]

  - repo: https://github.com/commitizen-tools/commitizen
    rev: v3.13.0
    hooks:
      - id: commitizen
        stages: [commit-msg]

  - repo: https://github.com/pre-commit/mirrors-prettier
    rev: v3.1.0
    hooks:
      - id: prettier
        types_or: [yaml, markdown, json]
```

## 3. Dependabot Configuration

### .github/dependabot.yml

```yaml
version: 2
updates:
  # Cargo dependencies
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 10
    reviewers:
      - "maintainers-team"
    labels:
      - "dependencies"
      - "rust"
    commit-message:
      prefix: "chore(deps)"
      include: "scope"
    groups:
      dev-dependencies:
        patterns:
          - "criterion"
          - "proptest"
          - "tempfile"
        update-types:
          - "minor"
          - "patch"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 5
    reviewers:
      - "maintainers-team"
    labels:
      - "dependencies"
      - "github-actions"
    commit-message:
      prefix: "chore(ci)"

  # Docker
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 5
    reviewers:
      - "maintainers-team"
    labels:
      - "dependencies"
      - "docker"
    commit-message:
      prefix: "chore(docker)"

  # NPM (for any frontend tooling)
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
      time: "09:00"
    open-pull-requests-limit: 10
    reviewers:
      - "maintainers-team"
    labels:
      - "dependencies"
      - "npm"
    commit-message:
      prefix: "chore(deps)"
    ignore:
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]
```

## 4. Code Coverage Configuration

### codecov.yml

```yaml
coverage:
  precision: 2
  round: down
  range: 70..100

  status:
    project:
      default:
        target: 80%
        threshold: 1%
        if_ci_failed: error

    patch:
      default:
        target: 80%
        threshold: 5%
        if_ci_failed: error

    changes:
      default:
        if_ci_failed: error

comment:
  layout: "reach, diff, flags, files"
  behavior: default
  require_changes: false
  require_base: false
  require_head: true

ignore:
  - "tests/"
  - "benches/"
  - "examples/"
  - "**/*_test.rs"
  - "**/tests.rs"

flags:
  unit:
    paths:
      - src/
    carryforward: true

  integration:
    paths:
      - tests/
    carryforward: true
```

## 5. Branch Protection Rules

Configure the following branch protection rules via GitHub Settings > Branches:

### Main Branch Protection

**Branch name pattern:** `main`

**Required checks:**
- Status checks must pass before merging:
  - CI / Check
  - CI / Format
  - CI / Clippy
  - CI / Test (ubuntu-latest, stable)
  - CI / Test (macos-latest, stable)
  - CI / Test (windows-latest, stable)
  - CI / Coverage
  - CI / Documentation
  - CI / Security Audit
  - Security / Dependency Audit
  - Security / SAST Scanning

**Pull request requirements:**
- Require a pull request before merging
- Require approvals: 2
- Dismiss stale pull request approvals when new commits are pushed
- Require review from Code Owners
- Require approval of the most recent reviewable push
- Require conversation resolution before merging

**Additional restrictions:**
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Require signed commits
- Include administrators
- Restrict who can push to matching branches
- Allow force pushes: Disabled
- Allow deletions: Disabled

### Develop Branch Protection

**Branch name pattern:** `develop`

**Required checks:**
- Status checks must pass before merging:
  - CI / Check
  - CI / Format
  - CI / Clippy
  - CI / Test (ubuntu-latest, stable)

**Pull request requirements:**
- Require a pull request before merging
- Require approvals: 1
- Require conversation resolution before merging

**Additional restrictions:**
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Allow force pushes: Disabled
- Allow deletions: Disabled

### Release Branch Protection

**Branch name pattern:** `release/*`

**Required checks:**
- All CI checks must pass
- Security scans must pass

**Pull request requirements:**
- Require approvals: 2
- Require review from Code Owners

**Additional restrictions:**
- Require signed commits
- Restrict who can push to matching branches
- Allow force pushes: Disabled
- Allow deletions: Disabled

## 6. Release Process

### 6.1 Versioning Strategy

Follow **Semantic Versioning 2.0.0** (semver.org):

- **MAJOR** version (X.0.0): Incompatible API changes
- **MINOR** version (0.X.0): Backward-compatible functionality additions
- **PATCH** version (0.0.X): Backward-compatible bug fixes

**Pre-release versions:**
- Alpha: `1.0.0-alpha.1`
- Beta: `1.0.0-beta.1`
- Release Candidate: `1.0.0-rc.1`

### 6.2 Changelog Format

Use **Keep a Changelog** format (keepachangelog.com):

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New features that have been added

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Now removed features

### Fixed
- Any bug fixes

### Security
- Vulnerabilities fixes

## [1.0.0] - 2025-01-15

### Added
- Initial release with core functionality
- RBAC system with user and service account support
- Data encryption at rest and in transit
- Comprehensive audit logging

### Security
- Implemented AES-256-GCM encryption
- Added secure key management with rotation
```

### 6.3 Release Checklist

**Pre-release Preparation:**

- [ ] Update version in `Cargo.toml`
- [ ] Update version in `Cargo.lock` (run `cargo build`)
- [ ] Update CHANGELOG.md with release notes
- [ ] Update documentation with new features/changes
- [ ] Run full test suite: `cargo test --all-features --workspace`
- [ ] Run benchmarks and compare with previous release
- [ ] Update dependencies: `cargo update`
- [ ] Run security audit: `cargo audit`
- [ ] Test installation from source
- [ ] Review and merge all pending PRs for the release

**Release Execution:**

- [ ] Create release branch: `git checkout -b release/vX.Y.Z`
- [ ] Commit version updates: `git commit -m "chore: bump version to vX.Y.Z"`
- [ ] Push release branch: `git push origin release/vX.Y.Z`
- [ ] Create and merge PR to main
- [ ] Tag release on main: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] Push tag: `git push origin vX.Y.Z`
- [ ] Wait for CI/CD pipelines to complete
- [ ] Verify GitHub release created with artifacts
- [ ] Verify Docker images published
- [ ] Verify crates.io publication
- [ ] Verify Helm chart published

**Post-release:**

- [ ] Announce release on social media/blog
- [ ] Update documentation site
- [ ] Close release milestone
- [ ] Create next milestone
- [ ] Merge main back to develop
- [ ] Update project board
- [ ] Monitor for critical issues in first 48 hours

### 6.4 Hotfix Process

For critical bugs in production:

1. Create hotfix branch from main: `git checkout -b hotfix/vX.Y.Z+1 main`
2. Apply minimal fix for critical issue
3. Bump PATCH version
4. Update CHANGELOG.md
5. Run tests and security checks
6. Create PR to main with "HOTFIX" prefix
7. Require expedited review (1 approver minimum)
8. Merge and tag immediately
9. Cherry-pick to develop if applicable
10. Monitor deployment closely

### 6.5 Commit Message Convention

Follow **Conventional Commits** (conventionalcommits.org):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, missing semicolons, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes
- `build`: Build system changes

**Examples:**
```
feat(auth): add OAuth2 provider support

Implement OAuth2 authentication flow with support for
Google and GitHub providers.

Closes #123
```

```
fix(vault): prevent data corruption on concurrent writes

Add proper locking mechanism to prevent race conditions
when multiple processes write to the same vault file.

Fixes #456
```

### 6.6 Version Bump Automation

Use `cargo-release` for automated version management:

```bash
# Install cargo-release
cargo install cargo-release

# Dry run
cargo release --dry-run patch

# Execute patch release
cargo release patch --execute

# Execute minor release
cargo release minor --execute

# Execute major release
cargo release major --execute
```

Configure in `Cargo.toml`:

```toml
[package.metadata.release]
sign-commit = true
sign-tag = true
pre-release-commit-message = "chore: release {{version}}"
tag-message = "Release {{version}}"
tag-name = "v{{version}}"
```

---

## Summary

This CI/CD pipeline provides:

1. **Comprehensive Testing**: Multi-platform testing on Linux, macOS, and Windows with stable and beta Rust
2. **Code Quality**: Automated formatting, linting, and documentation checks
3. **Security**: Dependency audits, SAST scanning, container scanning, and SBOM generation
4. **Performance**: Automated benchmarking with regression detection
5. **Automation**: Fully automated release process with binary builds, Docker images, and Helm charts
6. **Quality Gates**: Branch protection with required status checks and code reviews
7. **Dependency Management**: Automated dependency updates via Dependabot
8. **Coverage Tracking**: Code coverage reporting with threshold enforcement

All workflows are production-ready and follow industry best practices for Rust projects.
