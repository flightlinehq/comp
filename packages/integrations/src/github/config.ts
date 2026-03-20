import { getIntegrationHandler } from '../factory';
import { Logo } from './assets/logo';

// Get the handler from the factory
const githubHandler = getIntegrationHandler('github');

// Type the export directly with inline annotation
const config: {
  name: string;
  id: string;
  active: boolean;
  logo: React.ComponentType;
  short_description: string;
  guide_url: string;
  description: string;
  images: string[];
  settings: {
    id: string;
    label: string;
    description: string;
    type: string;
    required: boolean;
    value: string;
    placeholder?: string;
  }[];
  category: string;
  sync: boolean;
  fetch: any;
} = {
  name: 'GitHub',
  id: 'github',
  active: true,
  logo: Logo,
  short_description: 'Automated SOC 2 security checks for GitHub repositories.',
  guide_url: 'https://trycomp.ai/docs/cloud-tests/github',
  description:
    'Checks GitHub repository security settings including branch protection rules, Dependabot alerts, secret scanning, code scanning (CodeQL), repository visibility, signed commits, CODEOWNERS files, and pull request review requirements.',
  images: [],
  settings: [
    {
      id: 'GITHUB_TOKEN',
      label: 'Personal Access Token',
      description:
        'GitHub personal access token with repo, security_events, and admin:org scopes',
      type: 'text',
      required: true,
      value: '',
      placeholder: 'ghp_xxxxxxxxxxxx',
    },
    {
      id: 'GITHUB_REPOS',
      label: 'Repositories (optional)',
      description:
        'Comma-separated list of repository names to check (e.g. owner/repo1, owner/repo2). Leave empty to check all accessible repositories.',
      type: 'text',
      required: false,
      value: '',
      placeholder: 'owner/repo1, owner/repo2',
    },
  ],
  category: 'Development',
  sync: true,
  // Use the fetch method from the handler
  fetch: githubHandler?.fetch,
};

export default config;
