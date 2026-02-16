export default function handler(req, res) {
  res.status(200).json({
    domain_checks_month: 0,
    copy_checks_month: 0,
    subscription_tier: 'free'
  });
}
