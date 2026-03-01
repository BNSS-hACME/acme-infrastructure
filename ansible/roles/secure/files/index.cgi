#!/bin/bash
echo "Content-type: text/html"
echo ""
echo "<!DOCTYPE html>"
echo "<html><head><title>ACME Secure Server</title>"
echo "<style>"
echo "  body { font-family: sans-serif; background-color: #f4f4f9; color: #333; text-align: center; padding: 50px; }"
echo "  .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: inline-block; }"
echo "  h1 { color: #2c3e50; }"
echo "  .user { color: #e74c3c; font-weight: bold; font-size: 1.2em; }"
echo "</style>"
echo "</head><body>"
echo "<div class='container'>"
echo "<h1>Secret ACME Infrastructure</h1>"

if [ -n "$OIDC_CLAIM_preferred_username" ]; then
    echo "<p>Welcome, <span class='user'>${OIDC_CLAIM_preferred_username}</span>!</p>"
elif [ -n "$REMOTE_USER" ]; then
    echo "<p>Welcome, <span class='user'>${REMOTE_USER}</span>!</p>"
else
    echo "<p>Authenticated successfully.</p>"
fi

echo "</div>"
echo "</body></html>"
