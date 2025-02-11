# GitLab Vulnerability Receiver

The GitLab vulnerability receiver fetches vulnerability data from GitLab projects or groups using the vulnerability export API.

## Configuration

### Required Parameters

| Field | Type | Description |
|-------|------|-------------|
| `token` | string | GitLab API token with read_api scope |
| `url` | string | Full URL to GitLab project or group (e.g., "https://gitlab.com/mygroup/myproject" or "https://gitlab.com/mygroup") |
| `type` | string | Type of URL - either "project" or "group" |

### Optional Parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | string | "https://gitlab.com" | Base URL of GitLab instance |
| `poll_interval` | duration | 5m | How often to check for new vulnerabilities |
| `export_timeout` | duration | 30m | Maximum time to wait for export completion |
| `state_file` | string | "" | Path to file for storing state |

## Example Configuration

```yaml
receivers:
  gitlab_vulnerability:
    token: ${GITLAB_TOKEN}  # Use environment variable for sensitive data
    url: "https://gitlab.com/mygroup/myproject"  # For a project
    type: "project"
    # OR
    # url: "https://gitlab.com/mygroup"  # For a group
    # type: "group"
    base_url: "https://gitlab.com"  # Optional: for self-hosted GitLab
    poll_interval: 10m  # Optional: check every 10 minutes
    export_timeout: 1h  # Optional: wait up to 1 hour for large exports
    state_file: "/var/lib/otelcol/gitlab_vulns.state"  # Optional: persist state
```

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