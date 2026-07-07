import json
import os
import re
from groq import Groq

def run_rules(code):
    findings = []
    if re.search(r'(api_key|secret|token|password)\s*=\s*[\'"][A-Za-z0-9_\-]{16,}[\'"]', code, re.IGNORECASE):
        findings.append("Potential hardcoded secret or API key detected.")
    if re.search(r'\b(eval|exec)\s*\(', code):
        findings.append("Usage of eval() or exec() detected, which can lead to arbitrary code execution.")
    if re.search(r'SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?\s*[+]\s*[A-Za-z0-9_]+', code, re.IGNORECASE):
        findings.append("Potential SQL injection via string concatenation in SQL query.")
    if re.search(r'[\'"]http://[a-zA-Z0-9_\-\.]+[\'"]', code):
        findings.append("Hardcoded insecure HTTP URL detected. Use HTTPS.")
    if re.search(r'system_prompt\s*=\s*f[\'"].*?\{[^\}]+\}', code, re.IGNORECASE):
        findings.append("Potential prompt injection risk: untrusted input interpolated directly into a system prompt.")
    return findings

def handler(event, context):
    # Handle CORS preflight
    if event.get('httpMethod') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            'body': ''
        }

    try:
        body = json.loads(event.get('body', '{}'))
        code = body.get('code', '')

        if not code.strip():
            return {
                'statusCode': 400,
                'headers': {'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Code is empty'})
            }

        rule_findings = run_rules(code)

        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            return {
                'statusCode': 500,
                'headers': {'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'GROQ_API_KEY not set'})
            }

        client = Groq(api_key=api_key)

        prompt = f"""You are an expert security code reviewer specializing in AI-generated "vibe-coded" applications.
We have run static analysis and found these potential issues:
{json.dumps(rule_findings)}

Code to review:
```
{code}
```

Your task:
1. Explain each rule finding in plain language.
2. Assign a severity (Critical, High, Medium, Low).
3. Suggest a concrete fix as a corrected code snippet.
4. Do one independent pass to catch additional issues the rules missed.
5. Return ONLY valid JSON in this exact schema:
{{
  "findings": [
    {{
      "title": "Short title",
      "severity": "Critical|High|Medium|Low",
      "explanation": "Plain language explanation",
      "suggested_fix": "Corrected code snippet"
    }}
  ]
}}

If no issues found, return {{"findings": []}}.
Respond ONLY with valid JSON, nothing else."""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.2
        )

        result_json = response.choices[0].message.content

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            'body': result_json
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }
