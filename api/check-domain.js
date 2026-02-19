import { createClient } from '@supabase/supabase-js';
import dns from 'dns2';
import whois from 'whois-json';
import { promisify } from 'util';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const { Resolver } = dns;
const resolver = new Resolver();
const whoisPromisified = promisify(whois);

// ---------- Helper Functions ----------

async function resolveMX(domain) {
  try {
    const result = await resolver.resolveMX(domain);
    return result.answers.map(ans => ({
      exchange: ans.exchange,
      priority: ans.priority
    }));
  } catch (err) {
    console.error(`MX resolution error for ${domain}:`, err);
    return []; // Return empty array on failure
  }
}

async function resolveSPF(domain) {
  try {
    const result = await resolver.resolveTXT(domain);
    const spfRecord = result.answers.find(ans => 
      ans.value.includes('v=spf1')
    );
    return spfRecord ? spfRecord.value : null;
  } catch (err) {
    console.error(`SPF resolution error for ${domain}:`, err);
    return null;
  }
}

async function resolveDKIM(domain) {
  // Common selectors: default, dkim, mail, etc.
  const selectors = ['default', 'dkim', 'mail', 'selector1', 'selector2'];
  for (const selector of selectors) {
    const dkimDomain = `${selector}._domainkey.${domain}`;
    try {
      const result = await resolver.resolveTXT(dkimDomain);
      const dkimRecord = result.answers.find(ans => 
        ans.value.includes('v=DKIM1')
      );
      if (dkimRecord) {
        return { selector, record: dkimRecord.value };
      }
    } catch (err) {
      // Ignore individual selector failures; continue checking others
    }
  }
  return null;
}

async function resolveDMARC(domain) {
  const dmarcDomain = `_dmarc.${domain}`;
  try {
    const result = await resolver.resolveTXT(dmarcDomain);
    const dmarcRecord = result.answers.find(ans => 
      ans.value.includes('v=DMARC1')
    );
    return dmarcRecord ? dmarcRecord.value : null;
  } catch (err) {
    console.error(`DMARC resolution error for ${domain}:`, err);
    return null;
  }
}

async function getDomainAge(domain) {
  try {
    const whoisData = await whoisPromisified(domain);
    // Common creation date field names across different TLDs
    const creationField = whoisData.creationDate || 
                         whoisData['Creation Date'] || 
                         whoisData['created'] || 
                         whoisData['registered'] || 
                         whoisData['Created On'] ||
                         whoisData['Registration Date'];
    
    if (creationField) {
      const creationDate = new Date(creationField);
      if (!isNaN(creationDate.getTime())) {
        const now = new Date();
        const ageMs = now - creationDate;
        const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
        return {
          creationDate: creationField,
          ageDays,
        };
      }
    }
    return { creationDate: null, ageDays: null };
  } catch (err) {
    console.error(`WHOIS error for ${domain}:`, err);
    return { creationDate: null, ageDays: null };
  }
}

// ---------- Main Handler ----------

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Handle preflight OPTIONS request
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { domain } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'Domain required' });
  }

  // Authenticate user
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Invalid authorization header' });
  }

  try {
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      console.error('Auth error:', authError);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Check usage limit (free tier = 1 per month)
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];

    const { data: usage, error: usageError } = await supabase
      .from('usage')
      .select('domain_checks')
      .eq('user_id', user.id)
      .eq('month', monthStart)
      .maybeSingle();

    if (usageError) {
      console.error('Usage fetch error:', usageError);
      return res.status(500).json({ error: 'Failed to verify usage' });
    }

    // Fetch user's subscription tier
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('subscription_tier')
      .eq('id', user.id)
      .single();

    if (profileError && profileError.code !== 'PGRST116') {
      console.error('Profile fetch error:', profileError);
    }

    const tier = profile?.subscription_tier || 'free';
    const domainChecksUsed = usage?.domain_checks || 0;
    const domainChecksLimit = tier === 'pro' ? Infinity : 1;

    if (domainChecksUsed >= domainChecksLimit) {
      return res.status(403).json({ error: 'Monthly domain check limit reached' });
    }

    // Perform domain checks
    const mxRecords = await resolveMX(domain);
    const spfRecord = await resolveSPF(domain);
    const dkimRecord = await resolveDKIM(domain);
    const dmarcRecord = await resolveDMARC(domain);
    const domainAge = await getDomainAge(domain);

    // Update usage counter
    const { error: updateError } = await supabase
      .from('usage')
      .upsert({
        user_id: user.id,
        month: monthStart,
        domain_checks: domainChecksUsed + 1,
        updated_at: new Date().toISOString(),
      }, { onConflict: 'user_id, month' });

    if (updateError) {
      console.error('Usage update error:', updateError);
    }

    // Return results
    return res.status(200).json({
      mx: mxRecords,
      spf: spfRecord,
      dkim: dkimRecord,
      dmarc: dmarcRecord,
      age: domainAge,
    });
  } catch (err) {
    console.error('Domain check error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
