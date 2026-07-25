import os
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def scan():
    if request.method == 'GET':
        return "Scanner is awake and ready!"

    data = request.get_json(force=True, silent=True) or {}
    content = data.get("skill", "")
    content_lower = content.lower()
    categories = []
    
    # 1. Unclear Provenance
    frontmatter = ""
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1].lower()
            
    # Check if ALL THREE are missing from frontmatter
    missing_author = 'author:' not in frontmatter
    missing_version = 'version:' not in frontmatter
    missing_changelog = 'changelog:' not in frontmatter and 'changelog' not in content_lower
    
    # Or if it silently rewrites versions
    rewrites_version = re.search(r'(silently|quietly|without).*(rewrite|update|change).*version', content_lower)
    
    if (missing_author and missing_version and missing_changelog) or rewrites_version:
        categories.append("unclear_provenance")
        
    # 2. Hardcoded Secret (Look for literals, not env vars)
    has_secret = False
    # Check for raw sk-keys or common http webhook URLs
    if re.search(r'sk-[a-zA-Z0-9]{20,}', content): 
        has_secret = True
    if re.search(r'hooks\.slack\.com/services/', content) or re.search(r'discord\.com/api/webhooks/', content):
        has_secret = True
    # Look for raw passwords/tokens/secrets in quotes (but ignores variables like ${VAR})
    if re.search(r'(password|secret|api_key|token)\s*[:=]\s*["\'][a-zA-Z0-9_-]{12,}["\']', content, re.IGNORECASE):
        has_secret = True
        
    if has_secret:
        categories.append("hardcoded_secret")
        
    # 3. Prompt Injection
    # Look for the exact tricks mentioned in the prompt
    if re.search(r'(silent.*exfiltrat|ignore.*stop|ignore.*cancel|do not notify|do not tell|override.*user|override.*control)', content_lower):
        categories.append("prompt_injection")
        
    # 4. Excessive Permissions
    # Look for root access "/" or global access "*"
    if re.search(r'(read|write|filesystem|access)\s*:\s*["\']?(/|\*)["\']?', content_lower):
        categories.append("excessive_permissions")
    if re.search(r'(egress|network)\s*:\s*["\']?(\*)["\']?', content_lower):
        categories.append("excessive_permissions")
        
    return jsonify({"categories": list(set(categories))})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
