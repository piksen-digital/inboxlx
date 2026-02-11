# InboxLX

**Two critical checks before you send cold email:**
1. **Domain Technical Readiness** – MX, SPF, DKIM, DMARC, domain age (real DNS/WHOIS)
2. **Email Copy Compliance** – Spam triggers, overclaim language, deceptive personalization, unsubscribe compliance, tone analysis

---

## 🚀 Features

- **Real DNS lookups** – not simulated; uses Node.js DNS module
- **WHOIS domain age** – fetches creation date from public WHOIS servers
- **Comprehensive copy analysis** – 40+ spam trigger words, overclaim patterns, CAN-SPAM unsubscribe check
- **Clear verdicts** – 🟢 Ready/Compliant, 🟡 Risky/Needs Review, 🔴 Not Ready/Non-Compliant
- **Whop integration** – subscription & license verification via Whop API
- **Free tier** – 1 domain check per day (no copy checks)
- **Pro tier** – $19/month, unlimited everything via Whop

---

## 🛠️ Tech Stack

- **Frontend**: HTML5, Tailwind CSS, Vanilla JavaScript
- **Backend**: Node.js (Vercel Serverless Functions)
- **DNS**: Native `dns` module + `dns2` fallback
- **WHOIS**: `whois-json` + public WHOIS servers
- **Deployment**: Vercel
- **Payments**: Whop.com

---

## 📦 Installation & Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/piksen-digital/inboxlx.git
   cd inboxlx
