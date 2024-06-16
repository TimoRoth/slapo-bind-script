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
    char *bind_script_path;
    char *passwd_script_path;
} bind_script_info;

static ConfigTable bind_script_cfg[] = {
    { "bind_script_path", "string", 2, 2, 0,
      ARG_STRING|ARG_OFFSET, (void*)offsetof(bind_script_info, bind_script_path),
      "( OLcfgAt:56131.1 NAME 'olcBindScriptPath' "
      "DESC 'Path to script to execute on successful bind' "
      "EQUALITY caseExactMatch "
      "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
    { "passwd_script_path", "string", 2, 2, 0,
      ARG_STRING|ARG_OFFSET, (void*)offsetof(bind_script_info, passwd_script_path),
      "( OLcfgAt:56131.2 NAME 'olcPasswdScriptPath' "
      "DESC 'Path to script to execute on password change exop' "
      "EQUALITY caseExactMatch "
      "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
    { NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs bind_script_ocs[] = {
    { "( OLcfgOvOc:56131.1 "
      "NAME 'olcBindScriptConfig' "
      "DESC 'bind_script configuration' "
      "SUP olcOverlayConfig "
      "MAY ( olcBindScriptPath $ olcPasswdScriptPath ) )",
      Cft_Overlay, bind_script_cfg },
    { NULL, 0, NULL }
};

static AttributeDescription *ad_userPassword;


static int bind_script_passwd_exop(Operation *op, SlapReply *rs)
{
    slap_overinst *on = (slap_overinst*)op->o_bd->bd_info;
    bind_script_info *bsi = (bind_script_info*)on->on_bi.bi_private;
    req_pwdexop_s *qpw = &op->oq_pwdexop;
    Entry *entry;
    Attribute *attr;
    int res;

    char *args[2] = { bsi->passwd_script_path, NULL };
    FILE *rfp, *wfp;

    if (!bsi->passwd_script_path || !bsi->passwd_script_path[0])
        return SLAP_CB_CONTINUE;

    if (ber_bvcmp(&slap_EXOP_MODIFY_PASSWD, &op->ore_reqoid))
        return SLAP_CB_CONTINUE;

    op->o_bd->bd_info = (BackendInfo*)on->on_info;
    res = be_entry_get_rw(op, &op->o_req_ndn, NULL, NULL, 0, &entry);
    if (res != LDAP_SUCCESS)
        return res;
    attr = attr_find(entry->e_attrs, ad_userPassword);

    if (bind_script_forkandexec(args, &rfp, &wfp) == (pid_t)-1) {
        be_entry_release_r(op, entry);
        return -1;
    }

    fprintf(wfp, "PASSWD\n");
    fprintf(wfp, "msgid: %ld\n", (long)op->o_msgid);
    fprintf(wfp, "dn: %s\n", op->o_req_dn.bv_val);
    fprintf(wfp, "oldCred: %.*s\n", (int)qpw->rs_old.bv_len, qpw->rs_old.bv_val);
    fprintf(wfp, "newCred: %.*s\n", (int)qpw->rs_new.bv_len, qpw->rs_new.bv_val);
    if (attr)
        fprintf(wfp, "userPassword: %.*s\n", (int)attr->a_vals[0].bv_len, attr->a_vals[0].bv_val);
    fclose(wfp);
    be_entry_release_r(op, entry);

    res = SLAP_CB_CONTINUE;
    while(!feof(rfp)) {
        char line[64];
        errno = 0;

        if (fgets(line, sizeof(line), rfp) == NULL) {
            if (errno == EINTR)
                continue;

            res = SLAP_CB_CONTINUE;
            break;
        }

        if (strncasecmp(line, "OK", 2) == 0) {
            res = SLAP_CB_BYPASS;
            break;
        }

        res = SLAP_CB_CONTINUE;
        break;
    }

    fclose(rfp);

    return res;
}

static int bind_script_bind_response(Operation *op, SlapReply *rs)
{
    bind_script_info *bsi = (bind_script_info*)op->o_callback->sc_private;
    char *args[2] = { bsi->bind_script_path, NULL };
    FILE *wfp;

    if (rs->sr_err != LDAP_SUCCESS)
        return SLAP_CB_CONTINUE;

    if (!bsi->bind_script_path || !bsi->bind_script_path[0])
        return SLAP_CB_CONTINUE;

    if (bind_script_forkandexec(args, NULL, &wfp) == (pid_t)-1) {
        send_ldap_error(op, rs, LDAP_OTHER, "could not fork/exec");
        return -1;
    }

    fprintf(wfp, "BINDSUCCESS\n");
    fprintf(wfp, "msgid: %ld\n", (long)op->o_msgid);
    fprintf(wfp, "dn: %.*s\n", (int)op->o_req_dn.bv_len, op->o_req_dn.bv_val);
    fprintf(wfp, "method: %d\n", op->oq_bind.rb_method);
    fprintf(wfp, "credlen: %lu\n", op->oq_bind.rb_cred.bv_len);
    fprintf(wfp, "cred: %.*s\n", (int)op->oq_bind.rb_cred.bv_len, op->oq_bind.rb_cred.bv_val);
    fclose(wfp);

    return SLAP_CB_CONTINUE;
}


static int bind_script_bind(Operation *op, SlapReply *rs)
{
    slap_overinst *on = (slap_overinst*)op->o_bd->bd_info;
    bind_script_info *bsi = (bind_script_info*)on->on_bi.bi_private;
    slap_callback *cb;

    if (!bsi->bind_script_path || !bsi->bind_script_path[0]) {
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
    const char *err;

    if (slap_str2ad("userPassword", &ad_userPassword, &err) != LDAP_SUCCESS) {
        Debug(LDAP_DEBUG_ANY, "Failed finding userPassword attr: %s\n", err, 0, 0);
        return -1;
    }

    on->on_bi.bi_private = ch_calloc(1, sizeof(bind_script_info));

    return LDAP_SUCCESS;
}

static int bind_script_db_destroy(BackendDB *be, ConfigReply *cr)
{
    slap_overinst *on = (slap_overinst*)be->bd_info;
    bind_script_info *bsi = (bind_script_info*)on->on_bi.bi_private;

    free(bsi->bind_script_path);
    free(bsi->passwd_script_path);
    free(bsi);

    return LDAP_SUCCESS;
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
    bind_script.on_bi.bi_extended = bind_script_passwd_exop;

    bind_script.on_bi.bi_cf_ocs = bind_script_ocs;
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
