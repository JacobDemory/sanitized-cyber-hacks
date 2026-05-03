## SQL & Web Attacks Case Study

### Overview
This project explores common web vulnerabilities, particularly SQL injection, caused by improper input validation.

### Vulnerability
User input is directly incorporated into SQL queries without sanitization.

### Attack Concept
- Inject malicious SQL statements
- Manipulate database queries
- Extract or modify data

### Key Concepts
- SQL injection
- Input validation
- Parameterized queries

### Impact
- Database compromise
- Data leakage
- Authentication bypass

### Mitigation Strategies
- Use parameterized queries / prepared statements
- Validate and sanitize all user input
- Limit database permissions

### What I Learned
Web security failures often come from simple mistakes like trusting user input.