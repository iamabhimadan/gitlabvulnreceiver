# GitLab Vulnerability Receiver

The GitLab Vulnerability Receiver fetches vulnerability data from GitLab projects and groups using the GitLab Security API.

## Configuration

The GitLab Vulnerability Receiver monitors a single GitLab project or group at a time. The configuration requires:

- `token`: GitLab API token with read_api scope
- `paths`: Exactly one path configuration specifying:
  - `id`: GitLab project or group ID
  - `type`: Either "project" or "group"

Optional configurations:
- `base_url`: GitLab instance URL (default: "https://gitlab.com")
- `poll_interval`: How often to check for new vulnerabilities (default: 5m)
- `export_timeout`: Maximum time to wait for export completion (default: 30m)
- `state_file`: Path to file for storing state

### Example Configuration

For a project:
```yaml
receivers:
  gitlab_vulnerability:
    token: ${GITLAB_TOKEN}
    paths:
      - id: "12345"  # Single project ID
        type: "project"
```

For a group:
```yaml
receivers:
  gitlab_vulnerability:
    token: ${GITLAB_TOKEN}
    paths:
      - id: "67890"  # Single group ID
        type: "group"
```

Note: To monitor multiple projects or groups, create separate receiver instances.

## How it Works

1. The receiver monitors configured GitLab projects and groups for vulnerabilities
2. For each path:
   - Creates a vulnerability export request
   - Waits for export completion
   - Downloads and processes the CSV data
   - Converts vulnerabilities to OpenTelemetry logs
3. Uses state tracking to process only new or updated vulnerabilities
4. Emits vulnerability data as OpenTelemetry logs with attributes

## Resource Attributes

Each log record includes these resource attributes:
- `gitlab.project.id`: The GitLab project ID
- `gitlab.group.id`: The GitLab group ID (for group exports)
- `gitlab.export.id`: The vulnerability export ID

## Log Record Attributes

Each vulnerability is converted to a log record with these attributes:
- `vulnerability.severity`: Severity level
- `vulnerability.state`: Current state
- `vulnerability.scanner`: Scanner that detected it
- `vulnerability.identifier`: CVE or other identifier
- `vulnerability.project`: Project name
- `vulnerability.group`: Group name
- `vulnerability.tool`: Detection tool
- `vulnerability.details`: Additional details
- `vulnerability.detected_at`: Detection timestamp
- `vulnerability.location`: Where found
- `vulnerability.dismissal_reason`: Why dismissed (if applicable) 