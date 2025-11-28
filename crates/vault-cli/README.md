# Vault CLI

Enterprise command-line interface for LLM Data Vault - secure storage and anonymization for LLM training data.

## Installation

### From Source

```bash
cargo install --path crates/vault-cli
```

### Pre-built Binaries

Download from the releases page for your platform.

## Configuration

### Environment Variables

```bash
export VAULT_URL=https://vault.example.com
export VAULT_API_KEY=your-api-key
```

### Configuration File

```bash
# Initialize configuration
vault config init

# Set values
vault config set url https://vault.example.com
vault config set api_key your-api-key

# Show configuration
vault config show
```

### Multiple Profiles

```bash
# Create a new profile
vault config init production --url https://prod.vault.example.com

# Use a profile
vault --profile production datasets list
```

## Commands

### Authentication

```bash
# Login with username/password
vault auth login -u user@example.com

# Check current user
vault auth whoami

# Verify token is valid
vault auth verify

# Logout
vault auth logout
```

### Datasets

```bash
# List datasets
vault datasets list
vault datasets list --status active --format jsonl

# Create dataset
vault datasets create "Training Data" -d "Q4 fine-tuning" -f jsonl

# Get dataset details
vault datasets get ds_abc123

# Update dataset
vault datasets update ds_abc123 --name "New Name"

# Delete dataset
vault datasets delete ds_abc123

# Get statistics
vault datasets stats ds_abc123

# Archive/unarchive
vault datasets archive ds_abc123
vault datasets unarchive ds_abc123

# Trigger PII scan
vault datasets scan ds_abc123
```

### Records

```bash
# List records
vault records -d ds_abc123 list
vault records -d ds_abc123 list --status active --pii-status clean

# Create record from JSON
vault records -d ds_abc123 create --json '{"prompt":"...", "response":"..."}'

# Create from file
vault records -d ds_abc123 create --file data.json

# Create from stdin
cat data.json | vault records -d ds_abc123 create --stdin

# Import JSONL file
vault records -d ds_abc123 import data.jsonl

# Get record
vault records -d ds_abc123 get rec_xyz789 --content

# Delete record
vault records -d ds_abc123 delete rec_xyz789

# Get PII results
vault records -d ds_abc123 pii rec_xyz789

# Quarantine/release
vault records -d ds_abc123 quarantine rec_xyz789 --reason "Sensitive data"
vault records -d ds_abc123 release rec_xyz789
```

### PII Detection & Anonymization

```bash
# Detect PII in text
vault pii detect --text "Contact john@example.com"

# Detect from file
vault pii detect --file document.txt

# Anonymize text
vault pii anonymize --text "Email: john@example.com" --strategy redact
vault pii anonymize --text "SSN: 123-45-6789" --strategy mask

# Available strategies: redact, mask, replace, pseudonymize, generalize, encrypt, remove

# Check if text is clean
vault pii check --text "Some text without PII"

# List supported PII types
vault pii types

# Interactive mode
vault pii interactive
```

### Webhooks

```bash
# List webhooks
vault webhooks list

# Create webhook
vault webhooks create "Record Events" https://api.example.com/webhook \
  --event record.created \
  --event pii.detected \
  --secret "your-secret"

# Update webhook
vault webhooks update wh_abc123 --name "Updated Name"

# Enable/disable
vault webhooks enable wh_abc123
vault webhooks disable wh_abc123

# Test webhook
vault webhooks test wh_abc123

# View deliveries
vault webhooks deliveries wh_abc123

# Retry failed delivery
vault webhooks retry wh_abc123 del_xyz789

# Rotate secret
vault webhooks rotate-secret wh_abc123
```

### API Keys

```bash
# List API keys
vault api-keys list

# Create API key
vault api-keys create "CI/CD Key" \
  --permission datasets:read \
  --permission records:read \
  --rate-limit 1000

# Revoke API key
vault api-keys revoke key_abc123

# Rotate API key
vault api-keys rotate key_abc123
```

### Health Check

```bash
# Quick health check
vault health

# Detailed status
vault health --detailed
```

## Output Formats

```bash
# Table (default)
vault datasets list

# JSON
vault datasets list --format json

# Compact JSON
vault datasets list --format json-compact

# YAML
vault datasets list --format yaml

# Plain (for scripting)
vault datasets list --format plain
```

## Shell Completions

```bash
# Bash
vault completion bash > /etc/bash_completion.d/vault

# Zsh
vault completion zsh > "${fpath[1]}/_vault"

# Fish
vault completion fish > ~/.config/fish/completions/vault.fish

# PowerShell
vault completion powershell > vault.ps1
```

## Examples

### Bulk Import with PII Scanning

```bash
# Import dataset with automatic PII scanning
vault records -d ds_abc123 import training_data.jsonl --scan-pii

# Check for records with PII
vault records -d ds_abc123 list --pii-status detected
```

### CI/CD Integration

```bash
#!/bin/bash
set -e

# Validate data before upload
vault pii check --file new_data.jsonl
if [ $? -ne 0 ]; then
    echo "PII detected - aborting upload"
    exit 1
fi

# Import data
vault records -d $DATASET_ID import new_data.jsonl

# Verify import
COUNT=$(vault records -d $DATASET_ID count)
echo "Dataset now has $COUNT records"
```

### Export with Anonymization

```bash
# Get anonymized records
vault records -d ds_abc123 list --format json | \
  jq -c '.[]' | \
  while read record; do
    vault records -d ds_abc123 anonymized $(echo $record | jq -r '.id')
  done > anonymized_export.jsonl
```

## License

MIT
