export default function handler(req, res) {
  res.status(200).json({ subscription_tier: 'free' });
}
