import { GoogleGenerativeAI } from '@google/generative-ai';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  // CORS headers (as before)
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing authorization header' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid authorization header' });

  try {
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      console.error('Auth error:', authError);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Check subscription
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('subscription_tier')
      .eq('id', user.id)
      .single();

    if (profileError && profileError.code !== 'PGRST116') {
      console.error('Profile fetch error:', profileError);
    }
    if (profile?.subscription_tier !== 'pro') {
      return res.status(403).json({ error: 'Pro subscription required' });
    }

    const { text, tone } = req.body;
    if (!text) return res.status(400).json({ error: 'Text required' });

    const apiKey = process.env.GEMINI_API_KEY; // <-- changed from GOOGLE_AI_API_KEY
    if (!apiKey) {
      console.error('Missing GEMINI_API_KEY');
      return res.status(500).json({ error: 'AI service not configured' });
    }

    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' }); // faster model

    const prompt = `Rewrite the following cold email in a ${tone} tone. Keep the same meaning but improve it for better engagement and compliance. Do not include any explanations, just the rewritten email:\n\n${text}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 sec timeout

    const result = await model.generateContent(prompt, { signal: controller.signal });
    clearTimeout(timeoutId);
    const response = await result.response;
    const rewritten = response.text();

    return res.status(200).json({ rewritten });
  } catch (err) {
    console.error('AI rewrite error:', err);
    if (err.name === 'AbortError') {
      return res.status(504).json({ error: 'AI request timed out' });
    }
    return res.status(500).json({ error: 'AI generation failed' });
  }
}
