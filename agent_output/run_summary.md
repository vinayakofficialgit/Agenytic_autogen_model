**Executive Summary**

The security scan has identified three findings, with a total weighted score of 8. The most severe finding is the detection of a hardcoded password in `app/main.py` at line 12, which poses a high risk to the application's security. Two other findings are related to Dockerfile issues: an outdated OpenSSL version and the use of the root user.

**Top 3 Risks**

1. **Hardcoded Password**: The detection of a hardcoded password in `app/main.py` at line 12 poses a high risk to the application's security, as it can be easily discovered and exploited by attackers.
2. **Outdated OpenSSL Version**: The use of an outdated OpenSSL version in the Dockerfile increases the risk of vulnerabilities being exploited, potentially leading to data breaches or system compromise.
3. **Root User in Dockerfile**: The use of the root user in the Dockerfile introduces a security risk if not properly configured, which can lead to unauthorized access and potential exploitation.

**Prioritized Next Steps**

1. **Remediation: Update OpenSSL Version**
	* Command: `RUN apt-get update && apt-get install -y --no-install-recommends openssl1.1`
	* File: `Dockerfile`
2. **