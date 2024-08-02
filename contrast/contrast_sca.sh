# !/usr/bin/env bash

# Contrast Security SAST
# Taken from: https://pages.github.ibm.com/Supply-Chain-Security/Contrast-Security-SAST/docs/travis-integration/
# See also: https://pages.github.ibm.com/Supply-Chain-Security/Contrast-Security-SAST/docs/local-scanning/

echo "Download SAST scanner"
curl \
	-L -H 'Accept: application/vnd.github.v3.raw' \
	-s "https://${CONTRAST_PAT}@maven.pkg.github.com/Contrast-Security-Inc/sast-local-scan-runner/com.contrastsecurity.sast-local-scan-runner/${CONTRAST_AGENT_VERSION}/sast-local-scan-runner-${CONTRAST_AGENT_VERSION}.jar" \
	-o scanner.jar

echo "Change SAST scanner JAR file permission"
chmod 777 scanner.jar

echo "Zipping the source code for SAST scan"

# OWNER/NAME-OF-REPO
# Get the name of the repo
# e.g. OWNER/NAME-OF-REPO -> NAME-OF-REPO
REPO_NAME=$(echo "${TRAVIS_REPO_SLUG}" | cut -d'/' -f2)

# Zipping the source code
zip -qq -r "${REPO_NAME}".zip src

echo "Setting environment variables"
export CUST_FILE_TO_BE_SCANNED=${REPO_NAME}.zip
export CONTRAST_LOCAL_SCANNER_AGENT=${TRAVIS_BUILD_DIR}/scanner.jar
export CONTRAST_PROJECT_NAME="${REPO_NAME}"

echo "Configure Contrast SAST"

# Copy files from devops/contrast to current directory.
# This step is needed because reading auth.conf file is not using
# absolute path hence it needs to be in the same directory as contrast.py.
cp devops/contrast/* .

pip3 install -r requirements.txt

echo "Running SAST scan on $CONTRAST_PROJECT_NAME"

python3 contrast.py

printf "\nSAST scan finished.\n"

# Zip the scanned results
find REPORTS -type f -name "*.csv" | zip sast-report.zip -@

CRITICAL_ISSUES_ALLOWED=0
HIGH_ISSUES_ALLOWED=0

CRITICAL=$(grep -R --include "*.csv" "CRITICAL" . | grep -vc "REMEDIATED\|FIXED")
HIGH=$(grep -R --include "*.csv" "HIGH" . | grep -vc "REMEDIATED\|FIXED")
MEDIUM=$(grep -R --include "*.csv" "MEDIUM" . | grep -vc "REMEDIATED\|FIXED")
LOW=$(grep -R --include "*.csv" "LOW" . | grep -vc "REMEDIATED\|FIXED")
NOTE=$(grep -R --include "*.csv" "NOTE" . | grep -vc "REMEDIATED\|FIXED")

printf "\nCollecting SCAN results\nBRANCH: %s, COMMIT_VER: %s\nCRITICAL: %s\nHIGH: %s\nMEDIUM: %s\nLOW: %s\nNOTE: %s" "${TRAVIS_BRANCH}" "${TRAVIS_COMMIT}" "${CRITICAL}" "${HIGH}" "${MEDIUM}" "${LOW}" "${NOTE}"

printf "\nSCAN results collection finished\n"

# Stop Travis if got CRITICAL or HIGH vuls
if (( CRITICAL > CRITICAL_ISSUES_ALLOWED )); then
	echo "The company policy permits no more than ${CRITICAL_ISSUES_ALLOWED} Critical Severity issues"
elif (( HIGH > HIGH_ISSUES_ALLOWED )); then
	echo "The company policy permits no more than ${HIGH_ISSUES_ALLOWED} High Severity issues"
else
	echo "No Critical or High Severity issues found"
	exit 0
fi

echo "Security Gate build failed"

# Email to the recipients the report
# if and only if there are CRITICAL or HIGH vuls
if [[ "${EMAIL_RECIPIENTS}" ]]; then
	printf "\nSending email to the recipients\n"
	mutt -s "SAST scan result for travis_branch-${REPO_NAME}-${TRAVIS_BRANCH}:${TRAVIS_COMMIT}" -a sast-report.zip -- "$EMAIL_RECIPIENTS"
fi


exit 1
