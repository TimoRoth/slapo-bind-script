#include "portable.h"

#ifdef SLAPD_OVER_BIND_SCRIPT

#include <ldap.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/ctype.h>

#include "slap.h"
#include "slap-config.h"

#include "fork.h"


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
	  "MAY ( olcBindScriptPath ) )",
	  Cft_Overlay, bind_script_cfg },
	{ NULL, 0, NULL }
};

static int bind_script_bind_response(Operation *op, SlapReply *rs)
{
	bind_script_info *bsi = (bind_script_info*)op->o_callback->sc_private;
	char *args[2] = { bsi->script_path, NULL };
	FILE *wfp;

	if (rs->sr_err != LDAP_SUCCESS)
		return SLAP_CB_CONTINUE;

	if (!bsi->script_path || !bsi->script_path[0])
		return SLAP_CB_CONTINUE;

	if (forkandexec(args, NULL, &wfp) == (pid_t)-1) {
		send_ldap_error(op, rs, LDAP_OTHER, "could not fork/exec");
		return -1;
	}

	fprintf(wfp, "BINDSUCCESS\n");
	fprintf(wfp, "msgid: %ld\n", (long)op->o_msgid);
	fprintf(wfp, "dn: %s\n", op->o_req_dn.bv_val);
	fprintf(wfp, "method: %d\n", op->oq_bind.rb_method);
	fprintf(wfp, "credlen: %lu\n", op->oq_bind.rb_cred.bv_len);
	fprintf(wfp, "cred: %s\n", op->oq_bind.rb_cred.bv_val);
	fclose(wfp);

	return SLAP_CB_CONTINUE;
}


static int bind_script_bind(Operation *op, SlapReply *rs)
{
	slap_overinst *on = (slap_overinst*)op->o_bd->bd_info;
	bind_script_info *bsi = (bind_script_info*)on->on_bi.bi_private;
	slap_callback *cb;

	if (!bsi->script_path || !bsi->script_path[0]) {
		Debug(LDAP_DEBUG_ANY, "No bind script provided, skipping.", 0, 0, 0);
		return SLAP_CB_CONTINUE;
	}

	cb = op->o_tmpcalloc(sizeof(slap_callback), 1, op->o_tmpmemctx);
	cb->sc_response = bind_script_bind_response;
	cb->sc_private = bsi;
	cb->sc_next = op->o_callback->sc_next;
	op->o_callback->sc_next = cb;

	return SLAP_CB_CONTINUE;
}


static int bind_script_db_init(BackendDB *be, ConfigReply *cr)
{
	slap_overinst *on = (slap_overinst*)be->bd_info;

	on->on_bi.bi_private = ch_calloc(1, sizeof(bind_script_info));

	return 0;
}

static int bind_script_db_destroy(BackendDB *be, ConfigReply *cr)
{
	slap_overinst *on = (slap_overinst*)be->bd_info;
	bind_script_info *bsi = (bind_script_info*)on->on_bi.bi_private;

	free(bsi->script_path);
	free(bsi);

	return 0;
}

static slap_overinst bind_script;

int bind_script_initialize()
{
	int res;

	bind_script.on_bi.bi_type = "bind_script";
	bind_script.on_bi.bi_flags = SLAPO_BFLAG_SINGLE;

	bind_script.on_bi.bi_db_init = bind_script_db_init;
	bind_script.on_bi.bi_db_destroy = bind_script_db_destroy;

	bind_script.on_bi.bi_op_bind = bind_script_bind;

	res = config_register_schema(bind_script_cfg, bind_script_ocs);
	if (res)
		return res;

	return overlay_register(&bind_script);
}

#if SLAPD_OVER_BIND_SCRIPT == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[])
{
	return bind_script_initialize();
}
#endif

#endif // defined(SLAPD_OVER_BIND_SCRIPT)
