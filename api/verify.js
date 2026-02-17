export default function handler(req, res) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

  const html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verifying your email - InboxLX</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
</head>
<body class="bg-dark text-white font-sans min-h-screen flex items-center justify-center">
    <div class="text-center">
        <div class="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary mb-4"></div>
        <h1 class="text-2xl font-semibold mb-2">Verifying your email...</h1>
        <p class="text-gray-400">Please wait while we confirm your email address.</p>
    </div>

    <script>
        (async () => {
            const urlParams = new URLSearchParams(window.location.search);
            const token = urlParams.get('token');
            const type = urlParams.get('type') || 'signup';

            if (!token) {
                document.body.innerHTML = '<div class="text-center"><p class="text-red-400">Invalid verification link. Missing token.</p></div>';
                return;
            }

            const supabase = window.supabase.createClient(
                '${supabaseUrl}',
                '${supabaseAnonKey}'
            );

            try {
                const { data, error } = await supabase.auth.verifyOtp({
                    token: token,
                    type: type,
                });

                if (error) {
                    throw error;
                }

                // Store session in localStorage for the main app to pick up
                const session = data.session;
                if (session) {
                    localStorage.setItem('inboxlx_session', JSON.stringify({
                        token: session.access_token,
                        email: session.user.email
                    }));
                }

                // Redirect to main app
                window.location.href = '/';
            } catch (err) {
                console.error(err);
                document.body.innerHTML = \`<div class="text-center"><p class="text-red-400">Verification failed: \${err.message}</p></div>\`;
            }
        })();
    </script>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(html);
}
