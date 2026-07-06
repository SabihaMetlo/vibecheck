import json
import os
import re
from http.server import BaseHTTPRequestHandler
from groq import Groq

def run_rules(code):
    findings = []
    
    # 1. Hardcoded API keys/secrets
    if re.search(r'(api_key|secret|token|password)\s*=\s*[\'"][A-Za-z0-9_\-]{16,}[\'"]', code, re.IGNORECASE):
        findings.append("Potential hardcoded secret or API key detected.")
        
    # 2. eval()/exec() usage
    if re.search(r'\b(eval|exec)\s*\(', code):
        findings.append("Usage of eval() or exec() detected, which can lead to arbitrary code execution.")
        
    # 3. String-concatenated SQL queries
    if re.search(r'SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?\s*[+]\s*[A-Za-z0-9_]+', code, re.IGNORECASE) or re.search(r'SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?f["\'].*?\{.*?\}', code, re.IGNORECASE):
        findings.append("Potential SQL injection via string concatenation or interpolation in SQL query.")
        
    # 4. Overly permissive CORS headers
    if re.search(r'Access-Control-Allow-Origin.*?:\s*[\'"]\*[\'"]', code, re.IGNORECASE):
        findings.append("Overly permissive CORS header (Access-Control-Allow-Origin: *) detected.")
        
    # 5. Insecure hardcoded HTTP URLs
    if re.search(r'[\'"]http://[a-zA-Z0-9_\-\.]+[\'"]', code):
        findings.append("Hardcoded insecure HTTP URL detected. Use HTTPS.")
        
    # 6. Prompt-injection risk patterns
    if re.search(r'f[\'"](.*?)System.*?\{[^\}]+\}', code, re.IGNORECASE) or re.search(r'system_prompt\s*=\s*f[\'"].*?\{[^\}]+\}', code, re.IGNORECASE) or re.search(r'[\'"]System.*?(prompt)?[\'"]\s*\+\s*[A-Za-z0-9_]+', code, re.IGNORECASE):
        findings.append("Potential prompt injection risk: untrusted input interpolated directly into a system prompt.")
    if re.search(r'(os\.system|subprocess\.(call|run|Popen)|eval|exec)\s*\(\s*.*?(llm_output|response|completion|message)', code, re.IGNORECASE):
        findings.append("Potential arbitrary code execution: LLM output passed directly to shell command or execution engine.")

    return findings

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data.decode('utf-8'))
            code = body.get('code', '')
            
            if not code.strip():
                self.send_error_response(400, "Code is empty")
                return

            rule_findings = run_rules(code)
            
            api_key = os.environ.get("GROQ_API_KEY")
            if not api_key:
                self.send_error_response(500, "GROQ_API_KEY environment variable is not set")
                return
                
            client = Groq(api_key=api_key)
            
            prompt = f"""You are an expert security code reviewer specializing in AI-generated "vibe-coded" applications. 
The user has submitted a piece of code for review.
We have run some basic static analysis rules and found the following potential issues:
{json.dumps(rule_findings)}

Code to review:
```
{code}
```

Your task:
1. Explain each rule finding in plain language.
2. Assign a severity to each finding (Critical, High, Medium, Low).
3. Suggest a concrete fix as a corrected code snippet for each finding.
4. Do one independent pass over the code to catch any additional security issues the rules missed, and include them in the same format. Focus heavily on prompt injection, unsanitized inputs, and insecure configurations.
5. Return the response as a structured JSON object.

The JSON MUST have the following schema:
{{
  "findings": [
    {{
      "title": "Short title of the issue",
      "severity": "Critical|High|Medium|Low",
      "explanation": "Plain language explanation of why this is dangerous",
      "suggested_fix": "Corrected code snippet demonstrating the fix"
    }}
  ]
}}

If there are no security issues found at all, return {{"findings": []}}.
Respond ONLY with valid JSON."""

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.2
            )
            
            result_json = response.choices[0].message.content
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*') 
            self.end_headers()
            self.wfile.write(result_json.encode('utf-8'))
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_error_response(500, str(e))

    def send_error_response(self, status_code, message):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*') 
        self.end_headers()
        error_json = json.dumps({"error": message})
        self.wfile.write(error_json.encode('utf-8'))
