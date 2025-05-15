### What is CSRF?
- Cross-Site Request Forgery (CSRF) is a web security vulnerability where an attacker tricks a user’s browser into making unwanted requests to a web app in which the user is authenticated
- CSRF attacks exploit the fact that browsers automatically include credentials (like cookies) with each request, making it hard for the server to distinguish between real and forged requests
- These attacks typically target actions that change server state, such as changing a password, transferring funds, or updating account details

### best practices
- use csrf token for each user session, and for every form with state-changing action
- GET method allows csrf to be triggered by simple links or images
- validate values within the form
- reentering passwords or 2FA when performing state-changing action

Using built-in tools (such as Flask-WTF) allows for automatic csrf protection, making it better than creating manual code to perform the same