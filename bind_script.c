#include "portable.h"

#ifdef SLAPD_OVER_BIND_SCRIPT

#include <ldap.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/ctype.h>

#include "slap.h"
#include "slap-config.h"


typedef struct bind_script_info {
	char *script_path;
} bind_script_info;

static ConfigTable bind_script_cfg[] = {
	{ "bind_script_path", "string", 2, 2, 0,
	  ARG_STRING|ARG_OFFSET, (void*)offsetof(bind_script_info, script_path),
	  "( OLcfgAt:56131.1 NAME 'olcBindScriptPath' "
	  "DESC 'Path to script to execute on successful bind' "
	  "EQUALITY caseExactMatch "
	  "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs bind_script_ocs[] = {
	{ "( OLcfgOvOc:56131.1 "
	  "NAME 'olcBindScriptConfig' "
	  "DESC 'bind_script configuration' "
	  "SUP olcOverlayConfig "
	  "MUST ( olcBindScriptPath ) )",
	  Cft_Overlay, bind_script_cfg },
	{ NULL, 0, NULL }
};

static int bind_script_bind_response(Operation *op, SlapReply *rs)
{
	if (rs->sr_err != LDAP_SUCCESS)
		return SLAP_CB_CONTINUE;

	return SLAP_CB_CONTINUE;
}


static int bind_script_bind(Operation *op, SlapReply *rs)
{
	slap_callback *cb;
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;

	cb = op->o_tmpcalloc(sizeof(slap_callback), 1, op->o_tmpmemctx);
	cb->sc_response = bind_script_bind_response;
	cb->sc_next = op->o_callback->sc_next;
	op->o_callback->sc_next = cb;

	return SLAP_CB_CONTINUE;
}


static slap_overinst bind_script;

int bind_script_initialize()
{
	bind_script.on_bi.bi_type = "bind_script";
	bind_script.on_bi.bi_flags = SLAPO_BFLAG_SINGLE;

	bind_script.on_bi.bi_op_bind = bind_script_bind;

	return overlay_register(&bind_script);
}

#if SLAPD_OVER_BIND_SCRIPT == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[])
{
	return bind_script_initialize();
}
#endif

#endif // defined(SLAPD_OVER_BIND_SCRIPT)
