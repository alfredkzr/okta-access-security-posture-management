import { useState } from 'react';
import { cn } from '../lib/utils';

/**
 * Maps common Okta app names/labels to their favicon domains.
 * Keys are lowercase substrings matched against app_name or app_label.
 */
const APP_DOMAIN_MAP: Record<string, string> = {
  // Productivity
  'slack': 'slack.com',
  'office 365': 'microsoft.com',
  'office365': 'microsoft.com',
  'microsoft': 'microsoft.com',
  'google workspace': 'google.com',
  'google': 'google.com',
  'gmail': 'gmail.com',
  'zoom': 'zoom.us',
  'notion': 'notion.so',
  'asana': 'asana.com',
  'trello': 'trello.com',
  'monday': 'monday.com',
  'clickup': 'clickup.com',
  'confluence': 'atlassian.com',
  'jira': 'atlassian.com',
  'atlassian': 'atlassian.com',
  'dropbox': 'dropbox.com',
  'box': 'box.com',
  'airtable': 'airtable.com',
  'miro': 'miro.com',
  'figma': 'figma.com',
  'canva': 'canva.com',
  'linear': 'linear.app',

  // Dev / Infra
  'github': 'github.com',
  'gitlab': 'gitlab.com',
  'bitbucket': 'bitbucket.org',
  'aws': 'aws.amazon.com',
  'amazon web services': 'aws.amazon.com',
  'azure': 'azure.microsoft.com',
  'gcp': 'cloud.google.com',
  'datadog': 'datadoghq.com',
  'pagerduty': 'pagerduty.com',
  'splunk': 'splunk.com',
  'new relic': 'newrelic.com',
  'docker': 'docker.com',
  'vercel': 'vercel.com',
  'netlify': 'netlify.com',
  'heroku': 'heroku.com',
  'terraform': 'terraform.io',
  'sentry': 'sentry.io',
  'grafana': 'grafana.com',

  // HR / Finance
  'bamboohr': 'bamboohr.com',
  'bamboo': 'bamboohr.com',
  'workday': 'workday.com',
  'adp': 'adp.com',
  'gusto': 'gusto.com',
  'rippling': 'rippling.com',
  'paylocity': 'paylocity.com',
  'expensify': 'expensify.com',
  'brex': 'brex.com',
  'netsuite': 'netsuite.com',
  'quickbooks': 'quickbooks.intuit.com',

  // Security / Identity
  'okta': 'okta.com',
  'crowdstrike': 'crowdstrike.com',
  '1password': '1password.com',
  'lastpass': 'lastpass.com',
  'duo': 'duo.com',
  'zscaler': 'zscaler.com',
  'cloudflare': 'cloudflare.com',
  'snyk': 'snyk.io',
  'wiz': 'wiz.io',

  // CRM / Sales / Marketing
  'salesforce': 'salesforce.com',
  'hubspot': 'hubspot.com',
  'zendesk': 'zendesk.com',
  'intercom': 'intercom.com',
  'marketo': 'marketo.com',
  'mailchimp': 'mailchimp.com',
  'sendgrid': 'sendgrid.com',
  'twilio': 'twilio.com',
  'freshdesk': 'freshdesk.com',
  'servicenow': 'servicenow.com',

  // Communication
  'teams': 'teams.microsoft.com',
  'discord': 'discord.com',
  'webex': 'webex.com',

  // Other common
  'snowflake': 'snowflake.com',
  'tableau': 'tableau.com',
  'power bi': 'powerbi.com',
  'looker': 'looker.com',
  'dbt': 'getdbt.com',
  'stripe': 'stripe.com',
  'docusign': 'docusign.com',
};

/** Stable color from string hash — produces distinct hues */
function hashColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = ((hash % 360) + 360) % 360;
  return `hsl(${hue}, 50%, 40%)`;
}

/** Get domain for an app name by fuzzy matching against the lookup map */
function getDomain(appName: string): string | null {
  const lower = appName.toLowerCase();
  // Exact key match first
  if (APP_DOMAIN_MAP[lower]) return APP_DOMAIN_MAP[lower];
  // Substring match — check if any key is contained in the app name
  for (const [key, domain] of Object.entries(APP_DOMAIN_MAP)) {
    if (lower.includes(key)) return domain;
  }
  return null;
}

/** Get initials from app name (1-2 chars) */
function getInitials(name: string): string {
  const words = name.trim().split(/\s+/);
  if (words.length >= 2) {
    return (words[0][0] + words[1][0]).toUpperCase();
  }
  return name.substring(0, 2).toUpperCase();
}

interface AppIconProps {
  appName: string | null | undefined;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const sizeMap = {
  sm: { container: 'w-6 h-6', img: 16, text: 'text-[9px]' },
  md: { container: 'w-8 h-8', img: 20, text: 'text-[10px]' },
  lg: { container: 'w-10 h-10', img: 24, text: 'text-xs' },
};

export default function AppIcon({ appName, size = 'md', className }: AppIconProps) {
  const [imgError, setImgError] = useState(false);
  const s = sizeMap[size];
  const name = appName || 'Unknown';
  const domain = getDomain(name);

  // Show favicon if domain is known and image hasn't errored
  if (domain && !imgError) {
    return (
      <div className={cn(s.container, 'rounded-lg bg-white/[0.08] flex items-center justify-center shrink-0 overflow-hidden', className)}>
        <img
          src={`https://www.google.com/s2/favicons?domain=${domain}&sz=${s.img * 2}`}
          alt={name}
          width={s.img}
          height={s.img}
          className="object-contain"
          loading="lazy"
          onError={() => setImgError(true)}
        />
      </div>
    );
  }

  // Fallback: colored initial circle
  const color = hashColor(name);
  return (
    <div
      className={cn(s.container, 'rounded-lg flex items-center justify-center shrink-0', className)}
      style={{ backgroundColor: color + '33' }}
    >
      <span className={cn(s.text, 'font-semibold')} style={{ color }}>
        {getInitials(name)}
      </span>
    </div>
  );
}
