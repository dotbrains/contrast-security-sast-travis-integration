# Contrast Security SAST Integration with Travis CI
![Python](https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white)
![travisci](https://img.shields.io/badge/-TravisCI-4e4847?style=flat-square&logo=travisci&logoColor=e0da53)
![yaml](https://img.shields.io/badge/-YAML-black?style=flat-square&logo=yaml&logoColor=red)
![Linux](https://img.shields.io/badge/-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)

[Contrast Security](https://www.contrastsecurity.com/) provides a Static Application Security Testing (SAST) solution that can be integrated into your existing CI/CD pipeline for local, fast security scanning.

## Getting Started

To begin using Contrast Security, follow their onboarding process. Detailed onboarding documentation is available on the [Contrast Security website](https://www.contrastsecurity.com/onboarding).

Log in to the Contrast Security UI to obtain the necessary API key and credentials. Detailed instructions for getting credentials can be found in the [Contrast Security documentation](https://www.contrastsecurity.com/docs/getting-credentials).

## How to Use

### 1. Add the Contrast Security API Key to Travis CI

Ensure that Travis CI is enabled for your repository by visiting [Travis CI](https://travis-ci.com/).

Add the following environment variables to your repository's settings in Travis CI:

* `CONTRAST__API__ORGANIZATION` - Contrast Security organization ID
* `CONTRAST__API__SERVICE__KEY` - Contrast Security service key
* `CONTRAST__API__USER__NAME` - Contrast Security user name
* `CONTRAST__API__URL` - Contrast Security API URL
* `CONTRAST__API__API_KEY` - Contrast Security API key
* `CONTRAST__AUTH__TOKEN` - Contrast Security auth token
* `CONTRAST_AGENT_VERSION` - Contrast Security agent version
* `CONTRAST_PAT` - Contrast Security Personal Access Token
* `EMAIL_RECIPIENTS` - Email recipients for the report

For the `CONTRAST_PAT` and `CONTRAST_AGENT_VERSION`, contact the Contrast Security support team or refer to the documentation provided by them.

You can obtain `CONTRAST__API__ORGANIZATION`, `CONTRAST__API__SERVICE__KEY`, `CONTRAST__API__API_KEY`, and `CONTRAST__API__USER__NAME` by following the [getting credentials guide](https://www.contrastsecurity.com/docs/getting-credentials).

For the `CONTRAST__AUTH__TOKEN`, log in to your Contrast Security account and copy the token from your user settings.

You can refer to an example `.env` file, if available, in your project for reference.

### 2. Configure `.travis.yml`

Add the following configuration to your `.travis.yml` file:

```yaml
configs:
  - &CONTRAST_CONFIG
    - CONTRAST__API__API_KEY=${CONTRAST__API__API_KEY}
    - CONTRAST__API__ORGANIZATION=${CONTRAST__API__ORGANIZATION}
    - CONTRAST__API__SERVICE_KEY=${CONTRAST__API__SERVICE_KEY}
    - CONTRAST__API__URL=${CONTRAST__API__URL}
    - CONTRAST__API__USER_NAME=${CONTRAST__API__USER_NAME}
    - CONTRAST__AUTH__TOKEN=${CONTRAST__AUTH__TOKEN}
    - CONTRAST_AGENT_VERSION=${CONTRAST_AGENT_VERSION}
    - CONTRAST_PAT=${CONTRAST_PAT}
    - EMAIL_RECIPIENTS=${EMAIL_RECIPIENTS}

stages:
  - name: Static Code Analysis
    if: type IN (pull_request, push) AND branch IN (development, master, main)

jobs:
  include:
    - stage: Static Code Analysis
      env:
        - *CONTRAST_CONFIG
      addons:
        apt:
          packages:
            - mutt
            - sendmail
      script: bash contrast/contrast_sca.sh
```

### 3. Add the Contrast Security SAST Script

Clone the required repository and copy the `contrast` directory to the root of your project.

```bash
git clone \
 https://github.com/dotbrains/contrast-security-sast-travis-integration \
 contrast-security-SAST
mv contrast-security-SAST/contrast .
rm -rf contrast-security-SAST
```

## How Does `contrast_sca.sh` Work?

The script will:

1. Install and configure the Contrast Security SAST agent.
2. Bundle the project's *source* directory into a zip file.
3. Upload the zip file to the Contrast Security SAST server for scanning.
4. Parse the Contrast Security SAST report and send an email to the recipients specified in the `EMAIL_RECIPIENTS` environment variable if vulnerabilities marked as *Critical* or *High* are found.
5. Exit with a status code of `0` if no vulnerabilities are found; otherwise, it exits with a status code of `1` to prevent the pipeline from continuing until the vulnerabilities are addressed.

## Why Consider Using Contrast Security for SAST?

* **Low False Positives**: Contrast Security SAST provides fewer false positives compared to traditional SAST tools.
* **Comprehensive Coverage**: Integrating Contrast Security IAST with SAST provides full coverage for security testing.
* **Pipeline-Native Architecture**: Contrast SAST is built to seamlessly integrate with CI tools, automating scans with each commit or pull request.
* **Actionable Remediation Guidance**: Provides clear, actionable guidance for fixing vulnerabilities directly in the codebase.

## License

This software is free and may be redistributed under the terms specified in the [LICENSE] file.

[license]: LICENSE
