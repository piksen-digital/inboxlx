import { GoogleGenerativeAI } from '@google/generative-ai';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { text, tone, licenseKey } = req.body;

  // Verify license (pro needed)
  if (!licenseKey) {
    return res.status(403).json({ error: 'Pro subscription required' });
  }
  // (You would validate licenseKey with Whop here – simplified for demo)

  try {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });

    const prompt = `Rewrite the following cold email to be more ${tone} while preserving the core message and key points. Make it concise and professional. Only return the rewritten email, no extra text.\n\nOriginal:\n${text}`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const rewritten = response.text();

    res.status(200).json({ rewritten });
  } catch (error) {
    console.error('Gemini error:', error);
    res.status(500).json({ error: 'AI rewrite failed' });
  }
}
