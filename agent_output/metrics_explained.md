Here is a concise summary of the pull request:

**Summary:**

This pull request has failed due to high-severity findings from Semgrep and Trivy-FS. The Semgrep finding is a hardcoded password detected in `app/main.py` at line 12, which poses a significant security risk. The Trivy-FS findings are related to insecure settings in the Dockerfile, including an outdated OpenSSL version and using the `root` user.

**Recommendations:**

To remediate these issues, you should:

1. Replace the hardcoded password with a secure storage mechanism.
2. Update the OpenSSL version in the Dockerfile.
3. Change the default user in the Dockerfile from `root` to a non-root user.

Additionally, it is recommended to run automated tests and review configuration files to ensure that these changes do not introduce any regressions or errors.