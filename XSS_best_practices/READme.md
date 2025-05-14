## this is code to protect against cross-site scripting (XSS, R-XSS)

### Features: 
- input validation and sanitization through rejection of html/Javascript syntax, special characters
- content security policy to restrict script sources to trusted domains
- secure headers and cookies for browser-level attack mitigation and session cookie theft prevention

### This is a simple flask app for the sole purpose of studying XSS prevention