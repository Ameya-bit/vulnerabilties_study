## Reflected and Store Cross-site scripting

### cross-site scripting can be found by trying to inject scripts through inputs, get and post methods, URL parameters, and more
- Reflected is when the injected scripts are displayed in the web application
- Store is when the malicious code is stored in a server (database), and so can affect multiple users

### Best Practices: 
- input validation and sanitization through rejection of dangerous html/Javascript syntax, special characters
- content security policy to restrict script sources to trusted domains
- secure headers and cookies for browser-level attack mitigation and session cookie theft prevention

### This is a simple flask app for the sole purpose of studying XSS prevention