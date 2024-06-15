#ifndef SLAPO_BIND_SCRIPT_FORK_H
#define SLAPO_BIND_SCRIPT_FORK_H

LDAP_BEGIN_DECL

extern pid_t forkandexec LDAP_P((
	char **args,
	FILE **rfp,
	FILE **wfp));

LDAP_END_DECL

#endif
