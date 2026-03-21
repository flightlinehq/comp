/**
 * GitHub Integration Manifest
 *
 * This integration connects to GitHub to monitor repository security,
 * branch protection, and organization settings.
 */

import type { IntegrationManifest } from '../../types';
import { branchProtectionCheck } from './checks/branch-protection';
import { dependabotCheck } from './checks/dependabot';
import { sanitizedInputsCheck } from './checks/sanitized-inputs';

export const manifest: IntegrationManifest = {
  id: 'github',
  name: 'GitHub',
  description:
    'Connect GitHub to monitor repository security, branch protection, and organization settings.',
  category: 'Development',
  logoUrl: 'https://img.logo.dev/github.com?token=pk_AZatYxV5QDSfWpRDaBxzRQ',
  docsUrl: 'https://docs.trycomp.ai/integrations/github',

  // API configuration for ctx.fetch helper
  baseUrl: 'https://api.github.com',
  defaultHeaders: {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'CompAI-Integration',
  },

  auth: {
    type: 'api_key',
    config: {
      fields: [
        {
          key: 'token',
          label: 'Personal Access Token',
          description: 'GitHub PAT with repo, read:org, and security_events scopes',
          type: 'password',
          required: true,
          placeholder: 'github_pat_...',
        },
      ],
      headerName: 'Authorization',
      headerPrefix: 'Bearer',
      setupInstructions: `To create a GitHub Personal Access Token:
1. Go to GitHub Settings > Developer settings > Personal access tokens > Fine-grained tokens
2. Click "Generate new token"
3. Select the repositories you want to monitor
4. Grant read access to: Contents, Metadata, Administration, Secret scanning alerts, Dependabot alerts, Code scanning alerts
5. Click "Generate token" and copy it`,
      createAppUrl: 'https://github.com/settings/tokens?type=beta',
    },
  },

  capabilities: ['checks'],

  // Compliance checks that run daily and can auto-complete tasks
  checks: [branchProtectionCheck, dependabotCheck, sanitizedInputsCheck],

  isActive: true,
};

export default manifest;

// Re-export types for external use
export * from './types';
