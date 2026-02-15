// api/verify-subscription.js
export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { licenseKey } = req.body;
    if (!licenseKey) {
      return res.status(400).json({ valid: false, error: 'License key is required' });
    }

    // 1. Admin secret (internal testing only – never exposed)
    const ADMIN_SECRET = process.env.ADMIN_SECRET;
    if (ADMIN_SECRET && licenseKey === ADMIN_SECRET) {
      console.log('Admin access granted');
      return res.status(200).json({
        valid: true,
        tier: 'pro',
        admin: true,
        message: 'Admin access'
      });
    }

    // 2. Production: require Whop credentials
    const WHOP_API_KEY = process.env.WHOP_API_KEY;
    const WHOP_PRODUCT_ID = process.env.WHOP_PRODUCT_ID;

    if (!WHOP_API_KEY || !WHOP_PRODUCT_ID) {
      console.error('Whop API credentials not configured');
      return res.status(500).json({
        valid: false,
        error: 'License service not configured'
      });
    }

    // 3. Verify with Whop API – no fallback
    try {
      const response = await fetch('https://api.whop.com/api/v2/licenses/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${WHOP_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          license_key: licenseKey,
          product_id: WHOP_PRODUCT_ID
        })
      });

      if (!response.ok) {
        // Log but don't leak internal details
        console.error(`Whop API error: ${response.status}`);
        return res.status(401).json({ valid: false, error: 'Invalid license key' });
      }

      const data = await response.json();

      if (data.valid === true && data.status === 'active') {
        return res.status(200).json({
          valid: true,
          tier: 'pro',
          message: 'License verified'
        });
      } else {
        return res.status(401).json({ valid: false, error: 'Invalid or inactive license' });
      }
    } catch (error) {
      console.error('Whop API connection error:', error);
      return res.status(503).json({ valid: false, error: 'License service unavailable' });
    }
  } catch (error) {
    console.error('Subscription verification error:', error);
    res.status(500).json({ valid: false, error: 'Internal server error' });
  }
}      "maxDuration": 10,
      "memory": 512
    }
  },
  "rewrites": [
    {
      "source": "/",
      "destination": "/index.html"
    },
    {
      "source": "/api/:path*",
      "destination": "/api/:path*"
    }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-XSS-Protection",
          "value": "1; mode=block"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        }
      ]
    }
  ]
}
