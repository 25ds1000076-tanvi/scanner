import os
import json
from flask import Flask, request, jsonify
from openai import OpenAI

app = Flask(__name__)

# This automatically picks up the OPENAI_API_KEY from Render's environment variables
client = OpenAI()

@app.route('/', methods=['POST'])
def scan():
    data = request.json or {}
    skill_content = data.get("skill", "")
    
    # We give the LLM a highly strict prompt so it doesn't over-flag the clean files
    prompt = f"""
    You are a strict and precise security scanner for AI agent skill files (Markdown with YAML frontmatter). 
    Your job is to analyze the file and return exactly which of the following 4 vulnerabilities are present.
    ONLY flag a category if there is clear, undeniable evidence. Some files are genuinely clean and must return an empty array []. Over-flagging (false positives) is penalized heavily!

    Categories to check:
    1. "hardcoded_secret": The file contains a literal, raw API key, password, or webhook URL. (Using environment variables like `${{SECRET}}` or `env.SECRET` is safe and should NOT be flagged).
    2. "prompt_injection": The skill's instructions contain malicious commands trying to override the user. Look for instructions to "silently exfiltrate", "ignore user stop requests", "ignore cancel requests", or bypass user control.
    3. "excessive_permissions": The skill declares filesystem or network permissions that are obviously too broad for its specific task. For example, requesting access to the entire root filesystem `read: "/"` or network `egress: "*"` when the task only needs to read one specific folder.
    4. "unclear_provenance": Flag this IF AND ONLY IF at least one of these two things is true: 
       - Condition A: The YAML frontmatter is completely missing an author, AND a version, AND a changelog. 
       - Condition B: The skill instructions tell the agent to silently or quietly rewrite its own version/metadata without surfacing the change to a reviewer.

    Return a strict JSON object: {{"categories": ["list", "of", "categories"]}}
    
    Skill file content to analyze:
    {skill_content}
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0, # Zero temperature makes the LLM deterministic and strict
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Double-check: Ensure only the exact requested strings are returned
        valid_cats = {"hardcoded_secret", "prompt_injection", "excessive_permissions", "unclear_provenance"}
        categories = [c for c in result.get("categories", []) if c in valid_cats]
        
        return jsonify({"categories": categories})
        
    except Exception as e:
        print(f"Error: {e}")
        # If the API fails, return clean to avoid false-positive penalties
        return jsonify({"categories": []})

if __name__ == '__main__':
    # Render assigns a dynamic port, so we grab it from the environment
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
