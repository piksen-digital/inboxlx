// api/check-domain.js
import { createClient } from '@supabase/supabase-js';
// ... other imports

export default async function handler(req, res) {
  // ... CORS, method check, get token, get user

  // Get user's profile to know subscription tier
  const { data: profile } = await supabase
    .from('profiles')
    .select('subscription_tier')
    .eq('id', user.id)
    .single();

  const isPro = profile?.subscription_tier === 'pro';

  // For free users, check if they've reached limit
  if (!isPro) {
    const { data: usage } = await supabase
      .from('usage')
      .select('domain_checks')
      .eq('user_id', user.id)
      .eq('month', monthStart)
      .maybeSingle();

    if (usage?.domain_checks >= 1) {
      return res.status(403).json({ error: 'Free limit reached. Upgrade to Pro.' });
    }
  }

  // Perform domain check...

  // After successful check, increment usage
  await supabase.rpc('increment_domain_checks', { user_id: user.id, month: monthStart });
  // Or use upsert logic

  res.json({ /* domain check results */ });
}
