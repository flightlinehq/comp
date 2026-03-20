interface GitHubCredentials {
  GITHUB_TOKEN: string;
  GITHUB_REPOS?: string;
}

interface GitHubFinding {
  title: string;
  description: string;
  remediation: string;
  status: 'pass' | 'fail' | 'warning';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  resultDetails: any;
}

interface GitHubRepo {
  name: string;
  full_name: string;
  owner: { login: string };
  default_branch: string;
  visibility: string;
  private: boolean;
}

interface BranchProtection {
  required_pull_request_reviews?: {
    required_approving_review_count?: number;
    dismiss_stale_reviews?: boolean;
    require_code_owner_reviews?: boolean;
  };
  required_status_checks?: {
    strict: boolean;
    contexts: string[];
  };
  enforce_admins?: { enabled: boolean };
  allow_force_pushes?: { enabled: boolean };
  required_signatures?: { enabled: boolean };
  required_linear_history?: { enabled: boolean };
}

const API_BASE = 'https://api.github.com';

async function ghRequest(path: string, token: string): Promise<Response> {
  return globalThis.fetch(`${API_BASE}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
}

async function ghFetchJson<T>(path: string, token: string): Promise<T> {
  const res = await ghRequest(path, token);
  if (!res.ok) {
    throw new Error(`GitHub API ${path}: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

/**
 * Fetch all repos the token has access to, paginated
 */
async function getAllRepos(token: string): Promise<GitHubRepo[]> {
  const repos: GitHubRepo[] = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const batch = await ghFetchJson<GitHubRepo[]>(
      `/user/repos?per_page=${perPage}&page=${page}&sort=full_name`,
      token,
    );
    repos.push(...batch);
    if (batch.length < perPage) break;
    page++;
  }

  return repos;
}

/**
 * Filter repos by user-specified names (comma-separated owner/repo or repo names)
 */
function filterRepos(repos: GitHubRepo[], filter: string): GitHubRepo[] {
  const names = filter
    .split(',')
    .map((n) => n.trim().toLowerCase())
    .filter(Boolean);
  if (names.length === 0) return repos;

  return repos.filter(
    (r) => names.includes(r.full_name.toLowerCase()) || names.includes(r.name.toLowerCase()),
  );
}

// ─── Individual Checks ───────────────────────────────────────────

function checkRepoVisibility(repo: GitHubRepo): GitHubFinding {
  const isPrivate = repo.private;
  return {
    title: `Repository Visibility - ${repo.full_name}`,
    description: isPrivate
      ? `Repository ${repo.full_name} is private.`
      : `Repository ${repo.full_name} is public. Public repositories may expose source code and internal logic.`,
    remediation: isPrivate
      ? 'No action required.'
      : 'Navigate to repository Settings > Danger Zone > Change visibility to Private.',
    status: isPrivate ? 'pass' : 'warning',
    severity: isPrivate ? 'informational' : 'medium',
    resultDetails: { repo: repo.full_name, visibility: repo.visibility, private: repo.private },
  };
}

async function checkBranchProtection(
  repo: GitHubRepo,
  token: string,
): Promise<GitHubFinding[]> {
  const findings: GitHubFinding[] = [];
  const branch = repo.default_branch;
  let protection: BranchProtection | null = null;

  try {
    protection = await ghFetchJson<BranchProtection>(
      `/repos/${repo.full_name}/branches/${branch}/protection`,
      token,
    );
  } catch {
    findings.push({
      title: `Branch Protection Not Enabled - ${repo.full_name}`,
      description: `Default branch '${branch}' on ${repo.full_name} has no branch protection rules configured.`,
      remediation:
        'Enable branch protection rules: Settings > Branches > Add rule for the default branch. Require pull request reviews, status checks, and prevent force pushes.',
      status: 'fail',
      severity: 'critical',
      resultDetails: { repo: repo.full_name, branch, protection: null },
    });
    return findings;
  }

  // PR reviews required
  const prReviews = protection.required_pull_request_reviews;
  const prReviewsEnabled = !!prReviews;
  findings.push({
    title: `Pull Request Reviews Required - ${repo.full_name}`,
    description: prReviewsEnabled
      ? `Pull request reviews are required on the default branch '${branch}'.`
      : `Pull request reviews are NOT required on the default branch '${branch}'. Code can be merged without review.`,
    remediation: prReviewsEnabled
      ? 'No action required.'
      : 'Enable required pull request reviews in branch protection rules.',
    status: prReviewsEnabled ? 'pass' : 'fail',
    severity: prReviewsEnabled ? 'informational' : 'high',
    resultDetails: { repo: repo.full_name, branch, required_pull_request_reviews: prReviews },
  });

  // Min reviewers
  const minReviewers = prReviews?.required_approving_review_count ?? 0;
  findings.push({
    title: `Minimum Reviewers (${minReviewers}) - ${repo.full_name}`,
    description:
      minReviewers >= 2
        ? `Requires ${minReviewers} approving reviews before merge.`
        : minReviewers === 1
          ? `Only 1 approving review required. Consider increasing to at least 2 for better oversight.`
          : `No minimum reviewer count configured.`,
    remediation:
      minReviewers >= 2
        ? 'No action required.'
        : 'Set required approving review count to at least 2 in branch protection rules.',
    status: minReviewers >= 2 ? 'pass' : minReviewers === 1 ? 'warning' : 'fail',
    severity: minReviewers >= 2 ? 'informational' : minReviewers === 1 ? 'medium' : 'high',
    resultDetails: { repo: repo.full_name, branch, required_approving_review_count: minReviewers },
  });

  // Status checks
  const statusChecks = protection.required_status_checks;
  const statusChecksEnabled = !!statusChecks;
  findings.push({
    title: `Required Status Checks - ${repo.full_name}`,
    description: statusChecksEnabled
      ? `Required status checks are configured on the default branch.`
      : `No required status checks on the default branch. Code can be merged without passing CI.`,
    remediation: statusChecksEnabled
      ? 'No action required.'
      : 'Configure required status checks in branch protection rules to ensure CI passes before merge.',
    status: statusChecksEnabled ? 'pass' : 'fail',
    severity: statusChecksEnabled ? 'informational' : 'high',
    resultDetails: { repo: repo.full_name, branch, required_status_checks: statusChecks },
  });

  // Force push prevention
  const forcePushAllowed = protection.allow_force_pushes?.enabled ?? true;
  findings.push({
    title: `Force Push Prevention - ${repo.full_name}`,
    description: !forcePushAllowed
      ? `Force pushes are blocked on the default branch.`
      : `Force pushes are allowed on the default branch. This can rewrite history and bypass protections.`,
    remediation: !forcePushAllowed
      ? 'No action required.'
      : 'Disable force pushes in branch protection rules.',
    status: !forcePushAllowed ? 'pass' : 'fail',
    severity: !forcePushAllowed ? 'informational' : 'high',
    resultDetails: { repo: repo.full_name, branch, allow_force_pushes: forcePushAllowed },
  });

  return findings;
}

async function checkSignedCommits(
  repo: GitHubRepo,
  token: string,
): Promise<GitHubFinding> {
  // Try to get signature requirement from branch protection
  try {
    const res = await ghRequest(
      `/repos/${repo.full_name}/branches/${repo.default_branch}/protection/required_signatures`,
      token,
    );
    if (res.ok) {
      const data = (await res.json()) as { enabled: boolean };
      return {
        title: `Signed Commits Enforcement - ${repo.full_name}`,
        description: data.enabled
          ? `Signed commits are required on the default branch.`
          : `Signed commits are not required on the default branch.`,
        remediation: data.enabled
          ? 'No action required.'
          : 'Enable required signed commits in branch protection rules to ensure commit authenticity.',
        status: data.enabled ? 'pass' : 'warning',
        severity: data.enabled ? 'informational' : 'medium',
        resultDetails: { repo: repo.full_name, signed_commits_required: data.enabled },
      };
    }
  } catch {
    // Endpoint not available or no protection
  }

  return {
    title: `Signed Commits Enforcement - ${repo.full_name}`,
    description: `Signed commits are not required on the default branch '${repo.default_branch}'.`,
    remediation:
      'Enable required signed commits in branch protection rules to ensure commit authenticity.',
    status: 'warning',
    severity: 'medium',
    resultDetails: { repo: repo.full_name, signed_commits_required: false },
  };
}

async function checkDependabotAlerts(
  repo: GitHubRepo,
  token: string,
): Promise<GitHubFinding> {
  try {
    const res = await ghRequest(
      `/repos/${repo.full_name}/vulnerability-alerts`,
      token,
    );
    // 204 = enabled, 404 = disabled
    const enabled = res.status === 204;
    return {
      title: `Dependabot Alerts - ${repo.full_name}`,
      description: enabled
        ? `Dependabot vulnerability alerts are enabled.`
        : `Dependabot vulnerability alerts are not enabled. Vulnerable dependencies may go undetected.`,
      remediation: enabled
        ? 'No action required.'
        : 'Enable Dependabot alerts: Settings > Code security and analysis > Dependabot alerts.',
      status: enabled ? 'pass' : 'fail',
      severity: enabled ? 'informational' : 'high',
      resultDetails: { repo: repo.full_name, dependabot_alerts_enabled: enabled },
    };
  } catch {
    return {
      title: `Dependabot Alerts - ${repo.full_name}`,
      description: `Unable to determine Dependabot alerts status. The token may lack the required permissions.`,
      remediation:
        'Ensure the token has the "repo" or "security_events" scope to check Dependabot status.',
      status: 'warning',
      severity: 'medium',
      resultDetails: { repo: repo.full_name, dependabot_alerts_enabled: 'unknown' },
    };
  }
}

async function checkSecretScanning(
  repo: GitHubRepo,
  token: string,
): Promise<GitHubFinding> {
  try {
    // If we can list secret scanning alerts, it's enabled
    const res = await ghRequest(
      `/repos/${repo.full_name}/secret-scanning/alerts?per_page=1`,
      token,
    );
    // 200 = enabled (even if 0 alerts), 404 = not enabled
    const enabled = res.ok;
    return {
      title: `Secret Scanning - ${repo.full_name}`,
      description: enabled
        ? `Secret scanning is enabled on this repository.`
        : `Secret scanning is not enabled. Committed secrets (API keys, tokens) may go undetected.`,
      remediation: enabled
        ? 'No action required.'
        : 'Enable secret scanning: Settings > Code security and analysis > Secret scanning.',
      status: enabled ? 'pass' : 'fail',
      severity: enabled ? 'informational' : 'high',
      resultDetails: { repo: repo.full_name, secret_scanning_enabled: enabled },
    };
  } catch {
    return {
      title: `Secret Scanning - ${repo.full_name}`,
      description: `Unable to determine secret scanning status.`,
      remediation: 'Ensure the token has required permissions to check secret scanning status.',
      status: 'warning',
      severity: 'medium',
      resultDetails: { repo: repo.full_name, secret_scanning_enabled: 'unknown' },
    };
  }
}

async function checkCodeScanning(
  repo: GitHubRepo,
  token: string,
): Promise<GitHubFinding> {
  try {
    const res = await ghRequest(
      `/repos/${repo.full_name}/code-scanning/alerts?per_page=1`,
      token,
    );
    // 200 = code scanning configured, 404 = not set up, 403 = Advanced Security not enabled
    if (res.ok) {
      return {
        title: `Code Scanning (CodeQL) - ${repo.full_name}`,
        description: `Code scanning is configured on this repository.`,
        remediation: 'No action required.',
        status: 'pass',
        severity: 'informational',
        resultDetails: { repo: repo.full_name, code_scanning_enabled: true },
      };
    }

    // 403 means Advanced Security feature not enabled
    const status = res.status;
    return {
      title: `Code Scanning (CodeQL) - ${repo.full_name}`,
      description:
        status === 403
          ? `GitHub Advanced Security is not enabled on this repository. Code scanning requires Advanced Security.`
          : `Code scanning (CodeQL) is not configured. Vulnerabilities in source code may go undetected.`,
      remediation:
        'Set up code scanning with CodeQL: Security tab > Set up code scanning > Configure CodeQL analysis.',
      status: 'fail',
      severity: 'medium',
      resultDetails: { repo: repo.full_name, code_scanning_enabled: false, api_status: status },
    };
  } catch {
    return {
      title: `Code Scanning (CodeQL) - ${repo.full_name}`,
      description: `Unable to determine code scanning status.`,
      remediation: 'Ensure the token has required permissions to check code scanning status.',
      status: 'warning',
      severity: 'medium',
      resultDetails: { repo: repo.full_name, code_scanning_enabled: 'unknown' },
    };
  }
}

async function checkCodeowners(
  repo: GitHubRepo,
  token: string,
): Promise<GitHubFinding> {
  // CODEOWNERS can be in root, docs/, or .github/
  const paths = ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS'];

  for (const path of paths) {
    try {
      const res = await ghRequest(
        `/repos/${repo.full_name}/contents/${path}`,
        token,
      );
      if (res.ok) {
        return {
          title: `CODEOWNERS File - ${repo.full_name}`,
          description: `A CODEOWNERS file exists at '${path}', ensuring designated reviewers for code changes.`,
          remediation: 'No action required.',
          status: 'pass',
          severity: 'informational',
          resultDetails: { repo: repo.full_name, codeowners_path: path, exists: true },
        };
      }
    } catch {
      // continue checking other paths
    }
  }

  return {
    title: `CODEOWNERS File - ${repo.full_name}`,
    description: `No CODEOWNERS file found. Without it, there are no designated code review owners for critical paths.`,
    remediation:
      'Create a CODEOWNERS file in the repository root, .github/, or docs/ directory to define required reviewers for code changes.',
    status: 'warning',
    severity: 'medium',
    resultDetails: { repo: repo.full_name, codeowners_path: null, exists: false },
  };
}

// ─── Main Fetch ───────────────────────────────────────────────────

async function fetch(credentials: GitHubCredentials): Promise<GitHubFinding[]> {
  const { GITHUB_TOKEN, GITHUB_REPOS } = credentials;

  if (!GITHUB_TOKEN) {
    throw new Error('GitHub Personal Access Token is required.');
  }

  // Validate token
  console.log('Validating GitHub token...');
  const userRes = await ghRequest('/user', GITHUB_TOKEN);
  if (!userRes.ok) {
    throw new Error(
      `GitHub authentication failed (${userRes.status}). Please check your Personal Access Token.`,
    );
  }
  const user = (await userRes.json()) as { login: string };
  console.log(`Authenticated as ${user.login}`);

  // Get repos
  console.log('Fetching repositories...');
  let repos = await getAllRepos(GITHUB_TOKEN);

  if (GITHUB_REPOS) {
    repos = filterRepos(repos, GITHUB_REPOS);
    if (repos.length === 0) {
      throw new Error(
        `No repositories matched the filter: ${GITHUB_REPOS}. Ensure the names are correct and the token has access.`,
      );
    }
  }

  console.log(`Checking ${repos.length} repositories...`);

  const allFindings: GitHubFinding[] = [];

  for (const repo of repos) {
    console.log(`Checking ${repo.full_name}...`);

    // Run all checks for this repo
    const [
      branchProtectionFindings,
      signedCommits,
      dependabot,
      secretScanning,
      codeScanning,
      codeowners,
    ] = await Promise.all([
      checkBranchProtection(repo, GITHUB_TOKEN),
      checkSignedCommits(repo, GITHUB_TOKEN),
      checkDependabotAlerts(repo, GITHUB_TOKEN),
      checkSecretScanning(repo, GITHUB_TOKEN),
      checkCodeScanning(repo, GITHUB_TOKEN),
      checkCodeowners(repo, GITHUB_TOKEN),
    ]);

    // Visibility check is synchronous
    allFindings.push(checkRepoVisibility(repo));
    allFindings.push(...branchProtectionFindings);
    allFindings.push(signedCommits);
    allFindings.push(dependabot);
    allFindings.push(secretScanning);
    allFindings.push(codeScanning);
    allFindings.push(codeowners);
  }

  return allFindings;
}

export { fetch };
export type { GitHubCredentials, GitHubFinding };
