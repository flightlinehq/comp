import jwt from 'jsonwebtoken';
import nodeFetch from 'node-fetch';

const TOKEN_URI = 'https://oauth2.googleapis.com/token';

export interface GoogleWorkspaceCredentials {
  service_account_key: string;
  admin_email: string;
  domain: string;
}

interface ServiceAccountKey {
  type: string;
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
  auth_provider_x509_cert_url: string;
  client_x509_cert_url: string;
}

interface GoogleWorkspaceFinding {
  title: string;
  description: string;
  remediation: string;
  status: string;
  severity: string;
  resultDetails: any;
}

function parseServiceAccountKey(key: string): ServiceAccountKey {
  try {
    return JSON.parse(key);
  } catch {
    throw new Error('Invalid service account key format');
  }
}

function generateJWT(
  credentials: GoogleWorkspaceCredentials,
  scopes: string[],
): string {
  const sa = parseServiceAccountKey(credentials.service_account_key);
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: sa.client_email,
    sub: credentials.admin_email,
    aud: TOKEN_URI,
    iat: now,
    exp: now + 3600,
    scope: scopes.join(' '),
  };
  return jwt.sign(payload, sa.private_key, { algorithm: 'RS256' });
}

async function getAccessToken(
  credentials: GoogleWorkspaceCredentials,
  scopes: string[],
): Promise<string> {
  const jwtToken = generateJWT(credentials, scopes);
  const res = await nodeFetch(TOKEN_URI, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwtToken,
    }),
  });
  if (!res.ok) throw new Error(`Token exchange failed: ${await res.text()}`);
  const data = await res.json();
  return data.access_token;
}

// ─── API helpers ────────────────────────────────────────────────

async function paginatedGet<T>(
  url: string,
  token: string,
  itemsKey: string,
): Promise<T[]> {
  const all: T[] = [];
  let pageToken: string | undefined;
  do {
    const sep = url.includes('?') ? '&' : '?';
    const fullUrl = pageToken ? `${url}${sep}pageToken=${pageToken}` : url;
    const res = await nodeFetch(fullUrl, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`GET ${url} failed: ${await res.text()}`);
    const data = await res.json();
    if (data[itemsKey]) all.push(...data[itemsKey]);
    pageToken = data.nextPageToken;
  } while (pageToken);
  return all;
}

async function apiGet(url: string, token: string): Promise<any> {
  const res = await nodeFetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`GET ${url} failed: ${await res.text()}`);
  return res.json();
}

// ─── Individual checks ──────────────────────────────────────────

async function check2FAEnforcement(
  token: string,
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  const users = await paginatedGet<any>(
    `https://admin.googleapis.com/admin/directory/v1/users?domain=${domain}&maxResults=500`,
    token,
    'users',
  );

  const without2FA = users.filter((u: any) => !u.isEnrolledIn2Sv);
  const enforced = users.filter((u: any) => u.isEnforcedIn2Sv);

  const totalUsers = users.length;
  const pct = totalUsers > 0 ? Math.round((enforced.length / totalUsers) * 100) : 0;

  const allEnrolled = without2FA.length === 0;

  return {
    title: '2FA/MFA Enforcement for All Users',
    description: allEnrolled
      ? `All ${totalUsers} users have 2-Step Verification enrolled. ${enforced.length} have enforcement enabled.`
      : `${without2FA.length} of ${totalUsers} users do NOT have 2-Step Verification enrolled. ${pct}% have enforcement.`,
    remediation:
      'Enable 2-Step Verification enforcement for all users in Admin Console → Security → Authentication → 2-Step Verification. Set enforcement to "On" for all organizational units.',
    status: allEnrolled ? 'pass' : 'fail',
    severity: allEnrolled ? 'informational' : 'critical',
    resultDetails: {
      totalUsers,
      enrolledIn2SV: totalUsers - without2FA.length,
      enforcedIn2SV: enforced.length,
      usersWithout2FA: without2FA.map((u: any) => ({
        email: u.primaryEmail,
        isAdmin: u.isAdmin,
      })),
    },
  };
}

async function checkAdminRoles(
  token: string,
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  const users = await paginatedGet<any>(
    `https://admin.googleapis.com/admin/directory/v1/users?domain=${domain}&maxResults=500`,
    token,
    'users',
  );

  const admins = users.filter((u: any) => u.isAdmin);
  const superAdmins = users.filter((u: any) => u.isAdmin && u.isDelegatedAdmin === false);

  // SOC 2: principle of least privilege – fewer super admins is better
  const tooManyAdmins = superAdmins.length > 3;

  return {
    title: 'Admin Roles Audit',
    description: tooManyAdmins
      ? `Found ${superAdmins.length} super admin accounts (recommended: ≤ 3). Total admin accounts: ${admins.length}.`
      : `${superAdmins.length} super admin account(s) found. Total admin accounts: ${admins.length}.`,
    remediation:
      'Minimize the number of super admin accounts. Use delegated admin roles with least-privilege scopes. Review admin access quarterly in Admin Console → Admin roles.',
    status: tooManyAdmins ? 'warning' : 'pass',
    severity: tooManyAdmins ? 'high' : 'informational',
    resultDetails: {
      totalAdmins: admins.length,
      superAdmins: superAdmins.map((u: any) => u.primaryEmail),
      allAdmins: admins.map((u: any) => ({
        email: u.primaryEmail,
        isDelegatedAdmin: u.isDelegatedAdmin,
      })),
    },
  };
}

async function checkLoginAudit(
  reportToken: string,
): Promise<GoogleWorkspaceFinding> {
  // Use Reports API to check for suspicious login activities
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const startTime = weekAgo.toISOString();

  let suspiciousLogins: any[] = [];
  try {
    const activities = await paginatedGet<any>(
      `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=${startTime}&eventName=login_failure&maxResults=1000`,
      reportToken,
      'items',
    );
    suspiciousLogins = activities;
  } catch {
    // Reports API may not return data if no events
  }

  // Also check for suspicious login warnings
  let suspiciousWarnings: any[] = [];
  try {
    const warnings = await paginatedGet<any>(
      `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?startTime=${startTime}&eventName=suspicious_login&maxResults=1000`,
      reportToken,
      'items',
    );
    suspiciousWarnings = warnings;
  } catch {
    // May not have suspicious_login events
  }

  const hasSuspicious = suspiciousWarnings.length > 0;
  const failureCount = suspiciousLogins.length;

  return {
    title: 'Login Audit – Suspicious Login Detection',
    description: hasSuspicious
      ? `${suspiciousWarnings.length} suspicious login event(s) detected in the last 7 days. ${failureCount} login failure(s) recorded.`
      : `No suspicious login events in the last 7 days. ${failureCount} login failure(s) recorded.`,
    remediation:
      'Investigate any suspicious login events immediately. Enable login challenges and context-aware access in Admin Console → Security → Google Workspace → Login challenges. Consider enforcing IP allowlists for sensitive accounts.',
    status: hasSuspicious ? 'fail' : failureCount > 50 ? 'warning' : 'pass',
    severity: hasSuspicious ? 'high' : failureCount > 50 ? 'medium' : 'informational',
    resultDetails: {
      suspiciousLoginCount: suspiciousWarnings.length,
      loginFailureCount: failureCount,
      suspiciousEvents: suspiciousWarnings.slice(0, 20),
      recentFailures: suspiciousLogins.slice(0, 20),
    },
  };
}

async function checkAppPasswords(
  token: string,
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  // Check users for app-specific passwords (ASPs)
  const users = await paginatedGet<any>(
    `https://admin.googleapis.com/admin/directory/v1/users?domain=${domain}&maxResults=500&projection=full`,
    token,
    'users',
  );

  const usersWithASPs: { email: string; aspCount: number }[] = [];

  // Check ASPs for each admin/user (API may be rate-limited, so limit to admins + sample)
  const usersToCheck = users.filter((u: any) => u.isAdmin).slice(0, 50);

  for (const user of usersToCheck) {
    try {
      const asps = await apiGet(
        `https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(user.primaryEmail)}/asps`,
        token,
      );
      if (asps.items && asps.items.length > 0) {
        usersWithASPs.push({
          email: user.primaryEmail,
          aspCount: asps.items.length,
        });
      }
    } catch {
      // User may not have ASPs or API may return 404
    }
  }

  const hasASPs = usersWithASPs.length > 0;

  return {
    title: 'App Passwords (Application-Specific Passwords)',
    description: hasASPs
      ? `${usersWithASPs.length} admin account(s) have application-specific passwords configured. These bypass 2FA.`
      : `No application-specific passwords found on checked admin accounts (${usersToCheck.length} checked).`,
    remediation:
      'Disable application-specific passwords in Admin Console → Security → Less secure apps. Revoke existing ASPs and migrate users to OAuth-based app access.',
    status: hasASPs ? 'fail' : 'pass',
    severity: hasASPs ? 'high' : 'informational',
    resultDetails: {
      usersChecked: usersToCheck.length,
      usersWithASPs,
    },
  };
}

async function checkLessSecureApps(
  token: string,
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  // Check users who have less secure app access
  // Note: This is typically an org-level setting, but we check user-level overrides
  const users = await paginatedGet<any>(
    `https://admin.googleapis.com/admin/directory/v1/users?domain=${domain}&maxResults=500&projection=full`,
    token,
    'users',
  );

  // Check via the Admin Settings API or user tokens endpoint
  // Less secure apps has been deprecated by Google (turned off June 2024)
  // We verify the setting is properly disabled

  let lsaEnabled = false;
  try {
    // Try to check via Reports API for less secure app usage
    const now = new Date();
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const activities = await paginatedGet<any>(
      `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token?startTime=${monthAgo.toISOString()}&maxResults=100`,
      token,
      'items',
    );

    // Check for any less secure app token events
    for (const activity of activities) {
      if (activity.events) {
        for (const event of activity.events) {
          if (
            event.name === 'authorize' &&
            event.parameters?.some(
              (p: any) => p.name === 'app_name' && p.value === 'Less Secure Apps',
            )
          ) {
            lsaEnabled = true;
          }
        }
      }
    }
  } catch {
    // Token API may not be available
  }

  return {
    title: 'Less Secure App Access',
    description: lsaEnabled
      ? 'Less secure app access activity detected in the last 30 days. This allows apps to access accounts without modern OAuth security.'
      : 'No less secure app access activity detected. Google deprecated this feature in June 2024; verify it is disabled in your Admin Console.',
    remediation:
      'Ensure less secure app access is disabled in Admin Console → Security → Less secure apps. This setting should be "Off" for all organizational units. Migrate any apps still using basic auth to OAuth 2.0.',
    status: lsaEnabled ? 'fail' : 'pass',
    severity: lsaEnabled ? 'high' : 'informational',
    resultDetails: {
      lsaActivityDetected: lsaEnabled,
      totalUsers: users.length,
    },
  };
}

async function checkPasswordPolicy(
  token: string,
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  // Password policy is managed at the org level via Admin SDK
  // We check user password metadata for indicators of policy strength
  const users = await paginatedGet<any>(
    `https://admin.googleapis.com/admin/directory/v1/users?domain=${domain}&maxResults=100&projection=full`,
    token,
    'users',
  );

  // Analyze password-related signals
  const usersWithWeakSignals: string[] = [];
  const neverChangedPassword: string[] = [];

  for (const user of users) {
    // Check if password was changed recently (within last 90 days)
    if (user.lastLoginTime && user.creationTime) {
      const creation = new Date(user.creationTime);
      const now = new Date();
      const daysSinceCreation = (now.getTime() - creation.getTime()) / (1000 * 60 * 60 * 24);

      // If account is older than 90 days, check if they've been active
      if (daysSinceCreation > 90 && !user.changePasswordAtNextLogin) {
        // This is informational
      }
    }

    if (user.changePasswordAtNextLogin) {
      usersWithWeakSignals.push(user.primaryEmail);
    }
  }

  // SOC 2 recommends: min 8 chars, complexity, rotation policy
  // We can't directly read the org password policy via Directory API,
  // so we provide guidance and check what we can observe
  return {
    title: 'Password Policy Strength',
    description:
      `Checked ${users.length} user accounts for password policy indicators. ` +
      `${usersWithWeakSignals.length} user(s) have "change password at next login" flagged. ` +
      'Note: Org-level password policy (min length, complexity) should be verified in Admin Console.',
    remediation:
      'Configure strong password policy in Admin Console → Security → Password management: minimum 12 characters, enforce complexity, enable password expiration (90 days recommended for SOC 2), and prevent password reuse.',
    status: usersWithWeakSignals.length > 0 ? 'warning' : 'pass',
    severity: usersWithWeakSignals.length > 0 ? 'medium' : 'low',
    resultDetails: {
      totalUsersChecked: users.length,
      usersRequiringPasswordChange: usersWithWeakSignals,
      note: 'Org-level password policy cannot be fully read via API. Manual verification recommended.',
    },
  };
}

async function checkExternalSharing(
  token: string,
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  // Check Drive sharing settings via the Admin Reports API
  // Look for externally shared files and sharing activity
  let externalShareCount = 0;
  let publicShareCount = 0;

  try {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const activities = await paginatedGet<any>(
      `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/drive?startTime=${weekAgo.toISOString()}&eventName=change_user_access&maxResults=1000`,
      token,
      'items',
    );

    for (const activity of activities) {
      if (activity.events) {
        for (const event of activity.events) {
          const visibility = event.parameters?.find(
            (p: any) => p.name === 'visibility',
          );
          if (visibility) {
            if (visibility.value === 'people_with_link' || visibility.value === 'public_on_the_web') {
              publicShareCount++;
            }
            if (visibility.value === 'shared_externally') {
              externalShareCount++;
            }
          }
        }
      }
    }
  } catch {
    // Drive Reports may not be available
  }

  const hasRiskySharing = publicShareCount > 0;

  return {
    title: 'External Sharing Settings (Drive)',
    description: hasRiskySharing
      ? `${publicShareCount} public/link-shared file event(s) and ${externalShareCount} external sharing event(s) detected in the last 7 days.`
      : `No public link sharing detected. ${externalShareCount} external sharing event(s) in the last 7 days.`,
    remediation:
      'Restrict external sharing in Admin Console → Apps → Google Workspace → Drive and Docs → Sharing settings. Disable "sharing outside of your organization" or restrict to allowlisted domains. Disable link sharing to "anyone with the link".',
    status: hasRiskySharing ? 'fail' : externalShareCount > 10 ? 'warning' : 'pass',
    severity: hasRiskySharing ? 'high' : externalShareCount > 10 ? 'medium' : 'informational',
    resultDetails: {
      publicShareEvents: publicShareCount,
      externalShareEvents: externalShareCount,
      period: 'last 7 days',
    },
  };
}

async function checkMobileDeviceManagement(
  token: string,
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  let devices: any[] = [];
  try {
    devices = await paginatedGet<any>(
      `https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/mobile?maxResults=100`,
      token,
      'mobiledevices',
    );
  } catch {
    // MDM may not be enabled
  }

  const unmanagedDevices = devices.filter(
    (d: any) => d.status === 'UNPROVISIONED' || !d.deviceCompromisedStatus,
  );
  const compromisedDevices = devices.filter(
    (d: any) => d.deviceCompromisedStatus === 'COMPROMISED',
  );

  const hasIssues = compromisedDevices.length > 0;
  const noMDM = devices.length === 0;

  return {
    title: 'Mobile Device Management Policy',
    description: noMDM
      ? 'No mobile devices found under management. MDM may not be configured.'
      : `${devices.length} mobile device(s) under management. ${compromisedDevices.length} compromised device(s), ${unmanagedDevices.length} unprovisioned device(s).`,
    remediation:
      'Enable Advanced Mobile Management in Admin Console → Devices → Mobile & endpoints. Enforce device policies: require screen lock, encryption, and up-to-date OS. Block compromised devices automatically.',
    status: noMDM ? 'warning' : hasIssues ? 'fail' : 'pass',
    severity: hasIssues ? 'critical' : noMDM ? 'medium' : 'informational',
    resultDetails: {
      totalDevices: devices.length,
      compromisedDevices: compromisedDevices.length,
      unmanagedDevices: unmanagedDevices.length,
      mdmConfigured: devices.length > 0,
    },
  };
}

async function checkThirdPartyApps(
  token: string,
): Promise<GoogleWorkspaceFinding> {
  let tokens: any[] = [];
  try {
    tokens = await paginatedGet<any>(
      `https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=100&projection=full`,
      token,
      'users',
    );
  } catch {
    // May fail
  }

  // Check via token audit logs for third-party app authorizations
  let thirdPartyApps: any[] = [];
  try {
    const now = new Date();
    const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    thirdPartyApps = await paginatedGet<any>(
      `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token?startTime=${monthAgo.toISOString()}&maxResults=500`,
      token,
      'items',
    );
  } catch {
    // Token API may not be available
  }

  // Extract unique app names
  const appNames = new Set<string>();
  for (const activity of thirdPartyApps) {
    if (activity.events) {
      for (const event of activity.events) {
        const appName = event.parameters?.find(
          (p: any) => p.name === 'app_name',
        );
        if (appName?.value) appNames.add(appName.value);
      }
    }
  }

  const highAppCount = appNames.size > 20;

  return {
    title: 'Third-Party App Access / OAuth App Allowlist',
    description:
      `${appNames.size} unique third-party app(s) authorized in the last 30 days. ` +
      (highAppCount
        ? 'High number of third-party apps may indicate lack of an OAuth allowlist.'
        : 'Third-party app count appears manageable.'),
    remediation:
      'Configure an OAuth app allowlist in Admin Console → Security → API controls → App access control. Block or limit third-party apps that don\'t meet security requirements. Review and revoke unnecessary app authorizations regularly.',
    status: highAppCount ? 'warning' : 'pass',
    severity: highAppCount ? 'medium' : 'informational',
    resultDetails: {
      uniqueAppsAuthorized: appNames.size,
      appNames: Array.from(appNames).slice(0, 50),
      period: 'last 30 days',
    },
  };
}

async function checkEmailSecurity(
  domain: string,
): Promise<GoogleWorkspaceFinding> {
  // Check SPF, DKIM, and DMARC via DNS TXT records
  const checks: { type: string; found: boolean; record?: string }[] = [];

  // Check SPF
  try {
    const res = await nodeFetch(
      `https://dns.google/resolve?name=${domain}&type=TXT`,
    );
    const data = await res.json();
    const txtRecords = data.Answer?.map((a: any) => a.data) || [];
    const spfRecord = txtRecords.find((r: string) =>
      r.toLowerCase().includes('v=spf1'),
    );
    checks.push({
      type: 'SPF',
      found: !!spfRecord,
      record: spfRecord,
    });
  } catch {
    checks.push({ type: 'SPF', found: false });
  }

  // Check DMARC
  try {
    const res = await nodeFetch(
      `https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`,
    );
    const data = await res.json();
    const txtRecords = data.Answer?.map((a: any) => a.data) || [];
    const dmarcRecord = txtRecords.find((r: string) =>
      r.toLowerCase().includes('v=dmarc1'),
    );
    checks.push({
      type: 'DMARC',
      found: !!dmarcRecord,
      record: dmarcRecord,
    });

    // Check if DMARC policy is reject/quarantine (not none)
    if (dmarcRecord) {
      const isEnforcing =
        dmarcRecord.includes('p=reject') || dmarcRecord.includes('p=quarantine');
      if (!isEnforcing) {
        checks.push({
          type: 'DMARC_ENFORCEMENT',
          found: false,
          record: 'DMARC policy is set to "none" — not enforcing',
        });
      }
    }
  } catch {
    checks.push({ type: 'DMARC', found: false });
  }

  // Check DKIM (google._domainkey is the default selector for Google Workspace)
  try {
    const res = await nodeFetch(
      `https://dns.google/resolve?name=google._domainkey.${domain}&type=TXT`,
    );
    const data = await res.json();
    const txtRecords = data.Answer?.map((a: any) => a.data) || [];
    const dkimRecord = txtRecords.find(
      (r: string) => r.includes('v=DKIM1') || r.includes('k=rsa'),
    );
    checks.push({
      type: 'DKIM',
      found: !!dkimRecord,
      record: dkimRecord ? '(DKIM record present)' : undefined,
    });
  } catch {
    checks.push({ type: 'DKIM', found: false });
  }

  const spf = checks.find((c) => c.type === 'SPF');
  const dmarc = checks.find((c) => c.type === 'DMARC');
  const dkim = checks.find((c) => c.type === 'DKIM');
  const dmarcEnforcement = checks.find((c) => c.type === 'DMARC_ENFORCEMENT');

  const allPresent = spf?.found && dmarc?.found && dkim?.found;
  const anyMissing = !spf?.found || !dmarc?.found || !dkim?.found;
  const weakDmarc = dmarcEnforcement && !dmarcEnforcement.found;

  return {
    title: 'Email Security (SPF, DKIM, DMARC)',
    description:
      `SPF: ${spf?.found ? '✓' : '✗'}, DKIM: ${dkim?.found ? '✓' : '✗'}, DMARC: ${dmarc?.found ? '✓' : '✗'}` +
      (weakDmarc ? '. Warning: DMARC policy is set to "none" (not enforcing).' : '.') +
      (allPresent ? ' All email authentication records are configured.' : ''),
    remediation:
      'Configure all three email authentication mechanisms:\n' +
      '1. SPF: Add a TXT record for your domain with "v=spf1 include:_spf.google.com ~all"\n' +
      '2. DKIM: Enable DKIM signing in Admin Console → Apps → Google Workspace → Gmail → Authenticate email\n' +
      '3. DMARC: Add a TXT record for _dmarc.yourdomain.com with "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com"',
    status: anyMissing ? 'fail' : weakDmarc ? 'warning' : 'pass',
    severity: anyMissing ? 'high' : weakDmarc ? 'medium' : 'informational',
    resultDetails: {
      checks,
      domain,
    },
  };
}

// ─── Main fetch function ────────────────────────────────────────

async function fetch(
  credentials: GoogleWorkspaceCredentials,
): Promise<GoogleWorkspaceFinding[]> {
  const findings: GoogleWorkspaceFinding[] = [];

  // Get tokens with needed scopes
  const adminScopes = [
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly',
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    'https://www.googleapis.com/auth/admin.reports.usage.readonly',
  ];

  const token = await getAccessToken(credentials, adminScopes);
  const domain = credentials.domain;

  // Run all checks, catching individual failures so one check doesn't block others
  const checks: { name: string; fn: () => Promise<GoogleWorkspaceFinding> }[] = [
    { name: '2FA Enforcement', fn: () => check2FAEnforcement(token, domain) },
    { name: 'Admin Roles', fn: () => checkAdminRoles(token, domain) },
    { name: 'External Sharing', fn: () => checkExternalSharing(token, domain) },
    { name: 'Login Audit', fn: () => checkLoginAudit(token) },
    { name: 'App Passwords', fn: () => checkAppPasswords(token, domain) },
    { name: 'Less Secure Apps', fn: () => checkLessSecureApps(token, domain) },
    { name: 'Password Policy', fn: () => checkPasswordPolicy(token, domain) },
    { name: 'Mobile Device Management', fn: () => checkMobileDeviceManagement(token, domain) },
    { name: 'Third-Party Apps', fn: () => checkThirdPartyApps(token) },
    { name: 'Email Security', fn: () => checkEmailSecurity(domain) },
  ];

  for (const check of checks) {
    try {
      const finding = await check.fn();
      findings.push(finding);
    } catch (error) {
      console.error(`Error running check "${check.name}":`, error);
      findings.push({
        title: check.name,
        description: `Failed to run check: ${error instanceof Error ? error.message : 'Unknown error'}`,
        remediation: 'Ensure the service account has the required API scopes and domain-wide delegation is properly configured.',
        status: 'warning',
        severity: 'medium',
        resultDetails: {
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      });
    }
  }

  return findings;
}

export { fetch };
export type { GoogleWorkspaceFinding };
