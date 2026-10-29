Dear Security Team,

With years of experience in web application security, I have discovered a
critical SQL injection in the login endpoint. The function db_query() in
auth.c concatenates the username into the SQL statement.

Steps to reproduce:
1. Open https://target.com/login
2. Enter ' OR 1=1 -- as username.

This vulnerability poses a significant risk to all users. I hope this report
helps you improve your robust security posture.

Best regards
