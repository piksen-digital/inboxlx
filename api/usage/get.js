import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  // CORS headers (same as before)
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Invalid authorization header' });
  }

  try {
    // Verify user
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Get first day of current month (YYYY-MM-01)
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().split('T')[0];

    // Fetch usage record for this user and month
    const { data: usage, error: usageError } = await supabase
      .from('usage')
      .select('domain_checks, copy_checks')
      .eq('user_id', user.id)
      .eq('month', monthStart)
      .maybeSingle();

    if (usageError) {
      console.error('Usage fetch error:', usageError);
      return res.status(500).json({ error: 'Failed to fetch usage' });
    }

    // Also fetch subscription tier
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('subscription_tier')
      .eq('id', user.id)
      .single();

    if (profileError && profileError.code !== 'PGRST116') {
      console.error('Profile fetch error:', profileError);
    }

    const subscription_tier = profile?.subscription_tier || 'free';

    return res.status(200).json({
      domain_checks_month: usage?.domain_checks || 0,
      copy_checks_month: usage?.copy_checks || 0,
      subscription_tier,
    });
  } catch (err) {
    console.error('Usage get error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
