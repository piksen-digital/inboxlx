import dns from 'dns';
import { promisify } from 'util';
import fetch from 'node-fetch';

const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolve = promisify(dns.resolve);

// Cache for WHOIS results (simple in-memory cache)
const whoisCache = new Map();
const CACHE_TTL = 3600000; // 1 hour

// Timeout promise for DNS queries
const timeout = (ms) => new Promise((_, reject) => 
  setTimeout(() => reject(new Error(`Timeout after ${ms}ms`)), ms)
);

// Main handler for Vercel serverless function
export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Only accept POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { domain, licenseKey } = req.body;

    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Basic domain validation
    const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
    if (!domainRegex.test(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    // Verify subscription if license key is provided
    if (licenseKey) {
      const isValid = await verifyLicenseKey(licenseKey);
      if (!isValid) {
        return res.status(403).json({ error: 'Invalid license key' });
      }
    } else {
      // Free tier: limit to 1 check per hour per IP (simplified)
      const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      const cacheKey = `free_${clientIp}`;
      const lastCheck = whoisCache.get(cacheKey);
      
      if (lastCheck && Date.now() - lastCheck < 3600000) {
        return res.status(429).json({ 
          error: 'Free tier limit reached. Please subscribe for unlimited checks.',
          upgradeUrl: 'https://whop.com/inboxready-lite'
        });
      }
      whoisCache.set(cacheKey, Date.now());
    }

    // Perform all checks in parallel with timeout
    const checks = await Promise.race([
      performAllChecks(domain),
      timeout(15000) // 15 second timeout for all checks
    ]);

    // Determine verdict
    const verdict = determineVerdict(checks);
    const recommendations = generateRecommendations(checks, verdict);

    // Return results
    res.status(200).json({
      domain,
      ...checks,
      verdict,
      recommendations
    });

  } catch (error) {
    console.error('Error processing request:', error);
    
    if (error.message.includes('Timeout')) {
      return res.status(408).json({ 
        error: 'Request timeout. Some DNS servers may be slow to respond.' 
      });
    }
    
    res.status(500).json({ 
      error: 'An error occurred while checking the domain',
      details: error.message 
    });
  }
}

async function performAllChecks(domain) {
  const [mx, spf, dkim, dmarc, whois] = await Promise.allSettled([
    checkMX(domain),
    checkSPF(domain),
    checkDKIM(domain),
    checkDMARC(domain),
    checkWhois(domain)
  ]);

  return {
    mx: mx.status === 'fulfilled' ? mx.value : { error: mx.reason?.message || 'MX check failed' },
    spf: spf.status === 'fulfilled' ? spf.value : { error: spf.reason?.message || 'SPF check failed' },
    dkim: dkim.status === 'fulfilled' ? dkim.value : { error: dkim.reason?.message || 'DKIM check failed' },
    dmarc: dmarc.status === 'fulfilled' ? dmarc.value : { error: dmarc.reason?.message || 'DMARC check failed' },
    whois: whois.status === 'fulfilled' ? whois.value : { error: whois.reason?.message || 'WHOIS check failed' }
  };
}

async function checkMX(domain) {
  try {
    const records = await Promise.race([
      dnsResolveMx(domain),
      timeout(5000)
    ]);
    
    if (!records || records.length === 0) {
      return { exists: false };
    }

    // Sort by priority
    records.sort((a, b) => a.priority - b.priority);
    
    // Identify provider
    const provider = identifyProvider(records[0].exchange);
    
    return {
      exists: true,
      records: records.slice(0, 3), // Return top 3 records
      provider
    };
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return { exists: false };
    }
    throw error;
  }
}

async function checkSPF(domain) {
  try {
    const records = await Promise.race([
      dnsResolveTxt(domain),
      timeout(5000)
    ]);
    
    const spfRecords = records.flat().filter(record => 
      record.includes('v=spf1') || record.includes('v=spf')
    );
    
    if (spfRecords.length === 0) {
      return { exists: false };
    }

    const spfRecord = spfRecords[0];
    const hasMultiple = spfRecords.length > 1;
    const hasHardFail = spfRecord.includes('-all');
    const hasSoftFail = spfRecord.includes('~all');
    const hasNeutral = spfRecord.includes('?all');
    
    return {
      exists: true,
      record: spfRecord,
      valid: spfRecord.includes('v=spf1'),
      multiple: hasMultiple,
      policy: hasHardFail ? 'hardfail' : hasSoftFail ? 'softfail' : hasNeutral ? 'neutral' : 'none'
    };
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return { exists: false };
    }
    throw error;
  }
}

async function checkDKIM(domain) {
  // Check common DKIM selectors
  const commonSelectors = [
    'google', 'selector1', 'selector2', 'default', 'dkim', 
    's1', 's2', 'k1', 'k2', 'mx', 'mail'
  ];
  
  for (const selector of commonSelectors) {
    try {
      const dkimDomain = `${selector}._domainkey.${domain}`;
      const records = await Promise.race([
        dnsResolveTxt(dkimDomain),
        timeout(3000)
      ]);
      
      const dkimRecords = records.flat().filter(record => 
        record.includes('v=DKIM1') || record.includes('k=rsa')
      );
      
      if (dkimRecords.length > 0) {
        const record = dkimRecords[0];
        const keyMatch = record.match(/k=rsa;?\s*p=([A-Za-z0-9+/=\s]+)/i);
        const keyLength = keyMatch ? 
          Math.ceil(atob(keyMatch[1].replace(/\s/g, '')).length * 8) : 0;
        
        return {
          exists: true,
          selector: selector,
          record: record,
          keyLength: keyLength,
          keyStrength: keyLength >= 2048 ? 'strong' : keyLength >= 1024 ? 'medium' : 'weak'
        };
      }
    } catch (error) {
      // Continue to next selector
      continue;
    }
  }
  
  return { exists: false };
}

async function checkDMARC(domain) {
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const records = await Promise.race([
      dnsResolveTxt(dmarcDomain),
      timeout(5000)
    ]);
    
    const dmarcRecords = records.flat().filter(record => 
      record.includes('v=DMARC1')
    );
    
    if (dmarcRecords.length === 0) {
      return { exists: false };
    }

    const dmarcRecord = dmarcRecords[0];
    const policyMatch = dmarcRecord.match(/p=([^;\s]+)/);
    const subdomainPolicyMatch = dmarcRecord.match(/sp=([^;\s]+)/);
    const percentageMatch = dmarcRecord.match(/pct=([^;\s]+)/);
    const ruaMatch = dmarcRecord.match(/rua=([^;\s]+)/);
    
    return {
      exists: true,
      record: dmarcRecord,
      policy: policyMatch ? policyMatch[1] : 'none',
      subdomainPolicy: subdomainPolicyMatch ? subdomainPolicyMatch[1] : null,
      percentage: percentageMatch ? parseInt(percentageMatch[1]) : 100,
      reporting: ruaMatch ? ruaMatch[1] : null
    };
  } catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return { exists: false };
    }
    throw error;
  }
}

async function checkWhois(domain) {
  try {
    // Check cache first
    const cacheKey = `whois_${domain}`;
    const cached = whoisCache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data;
    }
    
    // Use public WHOIS servers
    const response = await Promise.race([
      fetch(`https://www.whois.com/whois/${domain}`),
      timeout(10000)
    ]);
    
    if (!response.ok) {
      throw new Error(`WHOIS lookup failed: ${response.status}`);
    }
    
    const text = await response.text();
    
    // Extract creation date (simplified parsing)
    let creationDate = null;
    const patterns = [
      /Creation Date:\s*(\d{4}-\d{2}-\d{2})/i,
      /Created On:\s*(\d{4}-\d{2}-\d{2})/i,
      /Registration Date:\s*(\d{4}-\d{2}-\d{2})/i,
      /Domain Create Date:\s*(\d{4}-\d{2}-\d{2})/i
    ];
    
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) {
        creationDate = match[1];
        break;
      }
    }
    
    if (!creationDate) {
      // Try alternative format
      const altPattern = /(\d{2}[-/]\d{2}[-/]\d{4})/;
      const altMatch = text.match(altPattern);
      if (altMatch) {
        creationDate = altMatch[1].replace(/\//g, '-');
      }
    }
    
    let ageInDays = null;
    if (creationDate) {
      const created = new Date(creationDate);
      if (!isNaN(created.getTime())) {
        ageInDays = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
      }
    }
    
    const result = {
      creationDate,
      ageInDays,
      rawData: text.substring(0, 500) // Return first 500 chars for debugging
    };
    
    // Cache the result
    whoisCache.set(cacheKey, {
      timestamp: Date.now(),
      data: result
    });
    
    return result;
  } catch (error) {
    console.error('WHOIS error:', error);
    return { 
      error: 'Could not retrieve WHOIS information',
      details: error.message 
    };
  }
}

function identifyProvider(exchange) {
  const hostname = exchange.toLowerCase();
  
  if (hostname.includes('google') || hostname.includes('gmail')) {
    return 'Google Workspace';
  }
  if (hostname.includes('outlook') || hostname.includes('office365') || hostname.includes('microsoft')) {
    return 'Microsoft 365';
  }
  if (hostname.includes('zoho')) {
    return 'Zoho Mail';
  }
  if (hostname.includes('yahoo')) {
    return 'Yahoo Mail';
  }
  if (hostname.includes('amazonaws') || hostname.includes('amazon')) {
    return 'Amazon SES';
  }
  if (hostname.includes('sendgrid') || hostname.includes('sg')) {
    return 'SendGrid';
  }
  if (hostname.includes('mailchimp') || hostname.includes('mandrill')) {
    return 'Mailchimp/Mandrill';
  }
  if (hostname.includes('mx') && hostname.includes('cloudflare')) {
    return 'Cloudflare Email Routing';
  }
  if (hostname.includes('protonmail') || hostname.includes('pm')) {
    return 'ProtonMail';
  }
  
  return 'Custom/Unknown';
}

function determineVerdict(checks) {
  // Rule-based logic as specified
  if (!checks.mx.exists) {
    return 'notready';
  }
  
  if (!checks.spf.exists || !checks.dkim.exists) {
    return 'notready';
  }
  
  const age = checks.whois.ageInDays;
  if (age && age < 30) {
    return 'risky';
  }
  
  return 'ready';
}

function generateRecommendations(checks, verdict) {
  const recommendations = [];
  
  if (!checks.mx.exists) {
    recommendations.push('Set up MX records to receive email. Without MX records, your domain cannot receive email.');
  }
  
  if (!checks.spf.exists) {
    recommendations.push('Set up SPF record to prevent spoofing. This is required for deliverability. Format: v=spf1 include:_spf.your-provider.com ~all');
  } else if (checks.spf.multiple) {
    recommendations.push('Multiple SPF records detected. This is invalid - consolidate all SPF mechanisms into a single record.');
  } else if (checks.spf.policy === 'neutral' || checks.spf.policy === 'none') {
    recommendations.push('Your SPF record uses a neutral policy (?all). Consider using ~all (softfail) or -all (hardfail) for better protection.');
  }
  
  if (!checks.dkim.exists) {
    recommendations.push('Set up DKIM record to prove emails are not altered in transit. Contact your email provider for DKIM setup instructions.');
  } else if (checks.dkim.keyStrength === 'weak') {
    recommendations.push('Your DKIM key is weak (less than 1024 bits). Consider upgrading to at least 2048-bit RSA key.');
  }
  
  if (!checks.dmarc.exists) {
    recommendations.push('Set up DMARC record to tell receivers how to handle failing emails. Start with p=none and add rua tag for reporting.');
  } else if (checks.dmarc.policy === 'none') {
    recommendations.push('Your DMARC policy is set to "none". Consider moving to p=quarantine after monitoring reports.');
  } else if (checks.dmarc.policy === 'quarantine') {
    recommendations.push('Your DMARC policy is set to "quarantine". Good! Monitor reports and consider moving to p=reject.');
  }
  
  if (checks.whois.ageInDays && checks.whois.ageInDays < 30) {
    recommendations.push(`Your domain is ${checks.whois.ageInDays} days old. Start with 20-30 emails per day for the first month to build reputation.`);
  }
  
  if (verdict === 'ready') {
    recommendations.push('Your domain is technically ready for cold email. Start with 20-30 emails per day and monitor bounce rates.');
  } else if (verdict === 'risky') {
    recommendations.push('Your domain is at risk. Follow the recommendations above and start with less than 20 emails per day.');
  } else {
    recommendations.push('Your domain is not ready for cold email. Fix the critical issues above before sending any emails.');
  }
  
  // Add general best practice
  recommendations.push('Always warm up new domains/IPs for 2-4 weeks before full-scale campaigns.');
  
  return recommendations;
}

// Simplified license verification (in production, integrate with Whop API)
async function verifyLicenseKey(licenseKey) {
  try {
    // In production, you would call Whop API here
    // For demo purposes, accept any non-empty string
    if (!licenseKey || licenseKey.trim() === '') {
      return false;
    }
    
    // Mock API call to Whop
    const response = await fetch('https://api.whop.com/api/v2/licenses/validate', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.WHOP_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        license_key: licenseKey,
        product_id: process.env.WHOP_PRODUCT_ID
      })
    });
    
    if (response.ok) {
      const data = await response.json();
      return data.valid === true;
    }
    
    return false;
  } catch (error) {
    console.error('License verification error:', error);
    // For demo, accept any license key
    return true;
  }
  }
