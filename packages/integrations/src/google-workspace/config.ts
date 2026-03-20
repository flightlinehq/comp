import { Logo } from './assets/logo';
import { fetch } from './src';

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
  name: 'Google Workspace',
  id: 'google-workspace',
  active: true,
  logo: Logo,
  short_description:
    'Automated SOC 2 security checks for Google Workspace configuration.',
  guide_url: 'https://trycomp.ai/docs/cloud-tests/google-workspace',
  description:
    'Checks Google Workspace security settings including 2FA enforcement, admin roles audit, external sharing policies, login anomaly detection, app passwords, less secure app access, password policy, mobile device management, third-party app access, and email security (SPF, DKIM, DMARC).',
  images: [],
  settings: [
    {
      id: 'service_account_key',
      label: 'Service Account Key (JSON)',
      description:
        'JSON key for a service account with domain-wide delegation enabled. Required scopes: Admin SDK Directory API, Reports API.',
      type: 'text',
      required: true,
      value: '',
      placeholder: '{"type": "service_account", "project_id": "...", ...}',
    },
    {
      id: 'admin_email',
      label: 'Admin Email',
      description:
        'Email address of a Google Workspace super admin to impersonate via domain-wide delegation.',
      type: 'text',
      required: true,
      value: '',
      placeholder: 'admin@yourdomain.com',
    },
    {
      id: 'domain',
      label: 'Domain',
      description: 'Your Google Workspace primary domain name.',
      type: 'text',
      required: true,
      value: '',
      placeholder: 'yourdomain.com',
    },
  ],
  category: 'Cloud',
  sync: true,
  fetch: fetch,
};

export default config;
