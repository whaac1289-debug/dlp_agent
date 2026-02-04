# Admin Guide

## Accessing the dashboard
- Navigate to the dashboard URL provided by your deployment.
- Authenticate with admin credentials defined in `DLP_ADMIN_EMAIL` and `DLP_ADMIN_PASSWORD`.

## Managing tenants
1. Create a tenant entry through the admin APIs or provisioning scripts.
2. Assign users to roles and tenants to enforce RBAC separation.

## Monitoring operations
- Review alerts and events by severity.
- Export events to SIEM for centralized security monitoring.

## License management
- Ensure `DLP_LICENSE_KEY` is present before startup.
- Rotate license keys following your internal key management policies.
