export default async function handler(req, res) {
  // Set CORS headers
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
      return res.status(400).json({ error: 'License key is required' });
    }

    // In production, verify with Whop API
    const isValid = await verifyWithWhop(licenseKey);

    if (isValid) {
      return res.status(200).json({
        valid: true,
        tier: 'pro',
        message: 'License key verified successfully'
      });
    } else {
      return res.status(401).json({
        valid: false,
        message: 'Invalid license key'
      });
    }
  } catch (error) {
    console.error('Subscription verification error:', error);
    res.status(500).json({ 
      error: 'Failed to verify subscription',
      details: error.message 
    });
  }
}

async function verifyWithWhop(licenseKey) {
  try {
    // Mock Whop API integration
    // In production, replace with actual Whop API call
    const WHOP_API_KEY = process.env.WHOP_API_KEY;
    const WHOP_PRODUCT_ID = process.env.WHOP_PRODUCT_ID;

    if (!WHOP_API_KEY || !WHOP_PRODUCT_ID) {
      console.warn('Whop API credentials not configured, using demo mode');
      // Demo mode: accept any license key
      return licenseKey.length > 5;
    }

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

    if (response.ok) {
      const data = await response.json();
      return data.valid === true && data.status === 'active';
    }

    return false;
  } catch (error) {
    console.error('Whop API error:', error);
    // Fallback to demo mode
    return licenseKey.length > 5;
  }
}
```

## 5. Vercel Configuration - vercel.json

```json
{
  "functions": {
    "api/check-domain.js": {
      "maxDuration": 30,
      "memory": 1024
    },
    "api/verify-subscription.js": {
      "maxDuration": 10,
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
