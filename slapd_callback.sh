#!/bin/bash
set -eo pipefail

read OP
while true; do
	read TAG VALUE || break

	case "$TAG" in
		dn:)
			DN="$VALUE"
			;;
		oldCred:)
			OLDPW="$VALUE"
			;;
		newCred:)
			NEWPW="$VALUE"
			;;
		userPassword:)
			PWHASH="$VALUE"
			;;
		method:)
			METHOD="$VALUE"
			;;
		cred:)
			CRED="$VALUE"
	esac
done

kadmin.ldap() {
	# This script runs as the ldap user
	kadmin -r CLUSTER.KLIMA.UNI-BREMEN.DE -p ldap/admin@CLUSTER.KLIMA.UNI-BREMEN.DE -k -t /etc/openldap/krb5.keytab "$@"
}

if [[ "$OP" == "PASSWD" ]]; then
	if [[ "$PWHASH" != "{SASL}"* ]]; then
		# Not a Kerberized account, continue normally.
		echo CONTINUE
		exit 0
	fi
	if [[ -z "$NEWPW" ]]; then
		>&2 echo "No new pw provided, can't operate"
		echo ERR
		exit 1
	fi

	if ! printf "%s\n%s\n" "$NEWPW" "$NEWPW" | kadmin.ldap cpw "${PWHASH:6}" >/tmp/kadmin_log 2>&1; then
		echo ERR
		exit 1
	fi

	echo OK
	exit 0
elif [[ "$OP" == "BINDSUCCESS" ]]; then
	if [[ "$DN" != *",ou=People,dc=cluster,dc=klima,dc=uni-bremen,dc=de" ]]; then
		# Not a user account, nothing to do
		exit 0
	fi
	if [[ "$PWHASH" == "{SASL}"* ]]; then
		# Already Kerberized, nothing to do
		exit 0
	fi
	if [[ "$METHOD" != 128 || -z "$CRED" ]]; then
		# Can't process non-plain or without credentials
		exit 0
	fi

	REALM="CLUSTER.KLIMA.UNI-BREMEN.DE"
	USER="${DN/,ou=People,dc=cluster,dc=klima,dc=uni-bremen,dc=de}"
	USER="${USER:3}@${REALM}"

	if ! printf "%s\n%s\n" "$CRED" "$CRED" | kadmin.ldap addprinc -x dn="$DN" "$USER"; then
		echo "Failed addprinc for $DN" >> /tmp/kerberized_accounts
		exit 1
	fi

	if ! printf "dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: {SASL}%s\n-\nreplace: pwdReset\npwdReset: FALSE\n" "$DN" "$USER" | ldapmodify -Y EXTERNAL -H ldapi://%2Frun%2Fopenldap%2Fslapd.sock; then
		echo "Failed ldapmodify for $DN" >> /tmp/kerberized_accounts
		exit 1
	fi

	echo "Migrated $DN" >> /tmp/kerberized_accounts

	exit 0
else
	>&2 echo "Unknown operation: $OP"
	echo ERR
	exit 0
fi
