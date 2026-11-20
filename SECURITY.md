# Security policy

This package is a static-analysis tool. Two kinds of report are especially
welcome:

- **A missed vulnerability class** — code the plugin should flag but does not
  (a false negative in the taint model).
- **A problem in the plugin itself** — anything that lets code under analysis
  affect the machine running the analysis.

Please report privately through GitHub: open the repository's **Security** tab
and choose **Report a vulnerability**. Do not open a public issue for something
that could be exploited.

Fixes are released as a patch version and noted in `CHANGELOG.md`. Only the
latest release is supported.
