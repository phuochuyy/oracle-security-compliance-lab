-- Security assessment checks, grouped like the CIS Oracle Database Benchmark sections
-- (2 parameters, 3 users/profiles, 4 privileges, 5 auditing) plus PCI-DSS checks for the card data.
-- Check IDs are this lab's own: the CIS PDF needs a registration I did not have when writing this.
-- One line per result: id|section|container|PASS/FAIL/ACCEPT/INFO|check|detail
-- "Oracle-maintained" accounts and roles (ORACLE_MAINTAINED = 'Y') are left out of the privilege checks.
-- usage: sqlplus -s / as sysdba @checks.sql <container>
set feedback off verify off heading off pages 0 lines 400 trimspool on
alter session set container = &1;
-- after the container switch, otherwise DBMS_OUTPUT is off in the PDB
set serveroutput on size unlimited
declare
  root boolean := sys_context('userenv', 'con_id') = 1;
  -- non Oracle-maintained grantees (users and roles)
  grantees constant varchar2(400) :=
    '(select username from dba_users where oracle_maintained = ''N''
      union all select role from dba_roles where oracle_maintained = ''N'')';
  -- accepted deviations: id -> reason (the check still runs, the status says ACCEPT)
  type t_acc is table of varchar2(200) index by varchar2(10);
  acc t_acc;

  procedure r(id varchar2, sec varchar2, ok boolean, title varchar2, detail varchar2 default null) is
    st varchar2(6) := case when ok then 'PASS' when acc.exists(id) then 'ACCEPT' else 'FAIL' end;
  begin
    dbms_output.put_line(id || '|' || sec || '|' || sys_context('userenv', 'con_name') || '|' || st || '|' ||
      title || '|' || substr(detail || case when st = 'ACCEPT' then ' - accepted: ' || acc(id) end, 1, 300));
  end;
  procedure info(id varchar2, sec varchar2, title varchar2, detail varchar2) is
  begin
    dbms_output.put_line(id || '|' || sec || '|' || sys_context('userenv', 'con_name') || '|INFO|' || title || '|' || substr(detail, 1, 300));
  end;
  function p(n varchar2) return varchar2 is v varchar2(4000);
  begin select upper(value) into v from v$parameter where name = n; return nvl(v, '(null)');
  exception when no_data_found then return '(n/a)'; end;
  function q(sql_text varchar2) return varchar2 is v varchar2(4000);
  begin execute immediate sql_text into v; return v; end;
  function n(lim varchar2) return number is   -- profile limit as a number, UNLIMITED = huge
  begin return case when lim = 'UNLIMITED' then 1e9 else to_number(lim) end;
  exception when others then return null; end;

begin
  acc('P04') := 'Data Guard redo transport and SYSDG/SYSBACKUP logins need the password file';
  acc('R04') := 'used by Oracle components and applications; removing needs per-component testing';

  --------------------------------------------------------------- 2 parameters (instance-wide: root only)
  if root then
    -- 23ai: traditional auditing is desupported and the parameter only drives it; the unified equivalent is
    -- a policy auditing all top-level statements of SYS (predefined ORA_ALL_TOPLEVEL_ACTIONS)
    declare v varchar2(400);
    begin
      v := q('select listagg(distinct e.policy_name, '','') within group (order by e.policy_name)
              from audit_unified_enabled_policies e join audit_unified_policies p on p.policy_name = e.policy_name
              where p.audit_option = ''ALL'' and p.audit_option_type = ''STANDARD ACTION''
                and e.entity_name in (''SYS'', ''ALL USERS'') and e.success = ''YES''');
      r('P01', '2 params', p('audit_sys_operations') = 'TRUE' or v is not null,
        'SYS top-level actions audited (AUDIT_SYS_OPERATIONS or unified policy)',
        'AUDIT_SYS_OPERATIONS=' || p('audit_sys_operations') || ', unified: ' || nvl(v, 'none'));
    end;
    r('P02', '2 params', p('global_names') = 'TRUE', 'GLOBAL_NAMES = TRUE', p('global_names'));
    r('P03', '2 params', p('os_roles') = 'FALSE', 'OS_ROLES = FALSE', p('os_roles'));
    r('P04', '2 params', p('remote_login_passwordfile') = 'NONE', 'REMOTE_LOGIN_PASSWORDFILE = NONE', p('remote_login_passwordfile'));
    r('P05', '2 params', p('remote_os_roles') = 'FALSE', 'REMOTE_OS_ROLES = FALSE', p('remote_os_roles'));
    r('P06', '2 params', to_number(p('sec_max_failed_login_attempts')) <= 3, 'SEC_MAX_FAILED_LOGIN_ATTEMPTS <= 3', p('sec_max_failed_login_attempts'));
    r('P07', '2 params', p('sec_protocol_error_further_action') like '%DROP%', 'SEC_PROTOCOL_ERROR_FURTHER_ACTION = (DROP,3)', p('sec_protocol_error_further_action'));
    r('P08', '2 params', p('sec_protocol_error_trace_action') = 'LOG', 'SEC_PROTOCOL_ERROR_TRACE_ACTION = LOG', p('sec_protocol_error_trace_action'));
    r('P09', '2 params', p('sec_return_server_release_banner') = 'FALSE', 'SEC_RETURN_SERVER_RELEASE_BANNER = FALSE', p('sec_return_server_release_banner'));
    r('P10', '2 params', p('sql92_security') = 'TRUE', 'SQL92_SECURITY = TRUE', p('sql92_security'));
    r('P11', '2 params', p('resource_limit') = 'TRUE', 'RESOURCE_LIMIT = TRUE', p('resource_limit'));
  end if;

  --------------------------------------------------------------- 3 users and profiles
  declare v varchar2(4000);
  begin
    v := q('select listagg(d.username, '','') within group (order by d.username) from dba_users_with_defpwd d
            join dba_users u on u.username = d.username where u.account_status = ''OPEN''');
    r('U01', '3 users', v is null, 'no OPEN account with a default password', nvl(v, 'none'));
    v := q('select listagg(username, '','') within group (order by username) from dba_users
            where password_versions like ''%10G%''');
    r('U02', '3 users', v is null, 'no 10G password hashes', nvl(v, 'none'));
    v := q('select listagg(db_link, '','') within group (order by db_link) from dba_db_links where owner = ''PUBLIC''');
    r('U03', '3 users', v is null, 'no PUBLIC database links', nvl(v, 'none'));
  end;
  -- password/resource limits of every profile used by an OPEN, non Oracle-maintained account
  for pr in (select distinct profile from dba_users where oracle_maintained = 'N' and account_status = 'OPEN'
              and authentication_type = 'PASSWORD' order by 1) loop
    declare
      bad varchar2(1000);
      function lim(res varchar2) return varchar2 is v varchar2(128);
      begin
        select limit into v from dba_profiles where profile = pr.profile and resource_name = res;
        if v = 'DEFAULT' then select limit into v from dba_profiles where profile = 'DEFAULT' and resource_name = res; end if;
        return v;
      end;
      procedure chk(res varchar2, ok boolean) is
      begin if not nvl(ok, false) then bad := bad || res || '=' || lim(res) || ' '; end if; end;
    begin
      chk('FAILED_LOGIN_ATTEMPTS',   n(lim('FAILED_LOGIN_ATTEMPTS')) <= 5);
      chk('PASSWORD_LOCK_TIME',      n(lim('PASSWORD_LOCK_TIME')) >= 1);
      chk('PASSWORD_LIFE_TIME',      n(lim('PASSWORD_LIFE_TIME')) <= 90);
      chk('PASSWORD_REUSE_MAX',      n(lim('PASSWORD_REUSE_MAX')) >= 20);
      chk('PASSWORD_REUSE_TIME',     n(lim('PASSWORD_REUSE_TIME')) >= 365);
      chk('PASSWORD_GRACE_TIME',     n(lim('PASSWORD_GRACE_TIME')) <= 5);
      chk('PASSWORD_VERIFY_FUNCTION', lim('PASSWORD_VERIFY_FUNCTION') not in ('NULL', 'UNLIMITED'));
      chk('SESSIONS_PER_USER',       n(lim('SESSIONS_PER_USER')) <= 10);
      chk('INACTIVE_ACCOUNT_TIME',   n(lim('INACTIVE_ACCOUNT_TIME')) <= 120);
      -- service profiles (*SVC*): only expiry may deviate, shown as ACCEPT
      if pr.profile like '%SVC%' and bad is not null
         and regexp_replace(bad, 'PASSWORD_(LIFE|GRACE)_TIME=[^ ]+ ', '') is null then
        acc('U10') := 'service account, credential in a wallet: no expiry, rotated by procedure';
      elsif acc.exists('U10') then acc.delete('U10');
      end if;
      r('U10', '3 users', bad is null, 'profile ' || pr.profile || ' meets the password/resource limits',
        nvl(bad, 'ok') || ' - users: ' || q('select listagg(username, '','') within group (order by username) from dba_users
          where profile = ''' || pr.profile || ''' and oracle_maintained = ''N'' and account_status = ''OPEN'''));
    end;
  end loop;

  --------------------------------------------------------------- 4 privileges
  declare
    procedure pub(id varchar2, title varchar2, pkgs varchar2) is v varchar2(4000);
    begin
      v := q('select listagg(table_name, '','') within group (order by table_name) from dba_tab_privs
              where grantee = ''PUBLIC'' and privilege = ''EXECUTE'' and owner = ''SYS''
                and table_name in (' || pkgs || ')');
      r(id, '4 privs', v is null, title, nvl(v, 'none'));
    end;
  begin
    pub('R01', 'no PUBLIC EXECUTE on network packages', '''UTL_TCP'',''UTL_SMTP'',''UTL_MAIL'',''UTL_HTTP'',''HTTPURITYPE'',''UTL_INADDR'',''DBMS_LDAP''');
    pub('R02', 'no PUBLIC EXECUTE on file packages', '''UTL_FILE'',''DBMS_ADVISOR'',''DBMS_FILE_TRANSFER'',''DBMS_BACKUP_RESTORE''');
    pub('R03', 'no PUBLIC EXECUTE on crypto packages', '''DBMS_CRYPTO'',''DBMS_OBFUSCATION_TOOLKIT''');
    -- general-purpose packages Oracle components rely on (DBMS_LOB and DBMS_RANDOM were in R02/R03 in the
    -- baseline run): kept, visible as ACCEPT
    pub('R04', 'no PUBLIC EXECUTE on dynamic SQL/LOB/job/java/random packages', '''DBMS_SQL'',''DBMS_SYS_SQL'',''DBMS_XMLGEN'',''DBMS_JOB'',''DBMS_SCHEDULER'',''DBMS_JAVA'',''DBMS_JAVA_TEST'',''DBMS_LOB'',''DBMS_RANDOM''');
  end;
  declare v varchar2(4000);
  begin
    v := q('select listagg(grantee || '':'' || privilege, '', '') within group (order by grantee, privilege) from dba_sys_privs
            where privilege like ''%ANY%'' and grantee in ' || grantees);
    r('R05', '4 privs', v is null, 'no ANY system privileges to non-Oracle grantees', nvl(v, 'none'));
    v := q('select listagg(grantee, '','') within group (order by grantee) from dba_role_privs
            where granted_role = ''DBA'' and grantee in ' || grantees);
    r('R06', '4 privs', v is null, 'DBA role not granted to non-Oracle grantees', nvl(v, 'none'));
    v := q('select listagg(grantee || '':'' || privilege, '', '') within group (order by grantee) from dba_sys_privs
            where admin_option = ''YES'' and grantee in ' || grantees);
    r('R07', '4 privs', v is null, 'no system privileges WITH ADMIN OPTION to non-Oracle grantees', nvl(v, 'none'));
    v := q('select listagg(grantee || '':'' || privilege, '', '') within group (order by grantee) from dba_sys_privs
            where privilege in (''ALTER SYSTEM'', ''AUDIT SYSTEM'', ''BECOME USER'', ''EXEMPT ACCESS POLICY'',
              ''EXEMPT REDACTION POLICY'', ''GRANT ANY OBJECT PRIVILEGE'', ''GRANT ANY ROLE'', ''GRANT ANY PRIVILEGE'',
              ''CREATE LIBRARY'', ''CREATE ANY LIBRARY'', ''SELECT ANY DICTIONARY'') and grantee in ' || grantees || ' or (grantee = ''PUBLIC''
              and privilege in (''ALTER SYSTEM'', ''SELECT ANY DICTIONARY''))');
    r('R08', '4 privs', v is null, 'no powerful system privileges to non-Oracle grantees', nvl(v, 'none'));
    v := q('select listagg(grantee || '':'' || table_name, '', '') within group (order by grantee) from dba_tab_privs
            where owner = ''SYS'' and table_name in (''USER$'', ''LINK$'', ''AUD$'', ''DEFAULT_PWD$'', ''ENC$'', ''USER_HISTORY$'',
              ''XS$VERIFIERS'', ''SCHEDULER$_CREDENTIAL'', ''CDB_LOCAL_ADMINAUTH$'', ''PDB_SYNC$'')
              and (grantee in ' || grantees || ' or grantee = ''PUBLIC'')');
    r('R09', '4 privs', v is null, 'no access to sensitive SYS tables', nvl(v, 'none'));
    if root then
      info('R10', '4 privs', 'password file users (admin privileges)',
        q('select listagg(username || '':'' || rtrim(case sysdba when ''TRUE'' then ''SYSDBA '' end || case sysoper when ''TRUE'' then ''SYSOPER '' end
           || case sysbackup when ''TRUE'' then ''SYSBACKUP '' end || case sysdg when ''TRUE'' then ''SYSDG '' end
           || case syskm when ''TRUE'' then ''SYSKM'' end), '', '') within group (order by username) from v$pwfile_users'));
    end if;
  end;

  --------------------------------------------------------------- 5 auditing (unified)
  r('A01', '5 audit', q('select value from v$option where parameter = ''Unified Auditing''') = 'TRUE',
    'pure unified auditing', q('select value from v$option where parameter = ''Unified Auditing'''));
  declare
    -- actions/privileges audited by an enabled policy for all users, successful ones too
    -- (ORA_LOGON_FAILURES alone does not count for LOGON)
    procedure need(id varchar2, title varchar2, opts varchar2) is v varchar2(4000);
    begin
      v := q('select listagg(o, '','') within group (order by o) from (
                select column_value o from table(sys.odcivarchar2list(' || opts || '))
                minus
                select p.audit_option from audit_unified_policies p
                  join audit_unified_enabled_policies e on e.policy_name = p.policy_name
                 where e.entity_name = ''ALL USERS'' and e.success = ''YES''
                   and nvl(p.object_schema, ''NONE'') = ''NONE''
                   and p.audit_option_type in (''STANDARD ACTION'', ''SYSTEM PRIVILEGE''))');
      r(id, '5 audit', v is null, title, case when v is null then 'all audited' else 'missing: ' || v end);
    end;
  begin
    need('A02', 'user and role management audited', '''CREATE USER'',''ALTER USER'',''DROP USER'',''CREATE ROLE'',''ALTER ROLE'',''DROP ROLE'',''SET ROLE''');
    need('A03', 'grants and revokes audited', '''GRANT'',''REVOKE''');
    need('A04', 'profile changes audited', '''CREATE PROFILE'',''ALTER PROFILE'',''DROP PROFILE''');
    need('A05', 'database links and synonyms audited', '''CREATE DATABASE LINK'',''ALTER DATABASE LINK'',''DROP DATABASE LINK'',''CREATE SYNONYM'',''DROP SYNONYM'',''CREATE PUBLIC SYNONYM'',''DROP PUBLIC SYNONYM''');
    need('A06', 'system changes audited', '''ALTER SYSTEM'',''ALTER DATABASE'',''CREATE PLUGGABLE DATABASE'',''ALTER PLUGGABLE DATABASE'',''DROP PLUGGABLE DATABASE''');
    need('A07', 'code and trigger DDL audited', '''CREATE PROCEDURE'',''ALTER PROCEDURE'',''DROP PROCEDURE'',''CREATE FUNCTION'',''DROP FUNCTION'',''CREATE PACKAGE'',''DROP PACKAGE'',''CREATE TRIGGER'',''ALTER TRIGGER'',''DROP TRIGGER''');
    need('A08', 'logon and logoff audited', '''LOGON'',''LOGOFF''');
  end;

  --------------------------------------------------------------- PCI-DSS: the card data (BANK schema)
  if q('select count(*) from dba_users where username = ''BANK''') = '1' then
    declare v varchar2(4000);
    begin
      v := q('select listagg(distinct t.tablespace_name, '','') within group (order by t.tablespace_name) from dba_tables t
              join dba_tablespaces s on s.tablespace_name = t.tablespace_name
              where t.owner = ''BANK'' and s.encrypted = ''NO''');
      r('C01', 'PCI 3.5', v is null, 'card data stored in encrypted tablespaces only', case when v is null then 'all encrypted' else 'not encrypted: ' || v end);
      v := q('select listagg(distinct p.policy_name, '','') within group (order by p.policy_name) from audit_unified_policies p
              join audit_unified_enabled_policies e on e.policy_name = p.policy_name
              where p.object_schema = ''BANK'' and p.object_name = ''CARDS''');
      r('C02', 'PCI 10.2', v is not null, 'access to BANK.CARDS audited', nvl(v, 'no enabled policy on BANK.CARDS'));
      v := q('select listagg(column_name || '':'' || function_type, '','') within group (order by column_name) from redaction_columns
              where object_owner = ''BANK'' and object_name = ''CARDS'' and column_name = ''PAN''');
      r('C03', 'PCI 3.4', v is not null, 'PAN masked for non-privileged readers (redaction)', nvl(v, 'no redaction policy on CARDS.PAN'));
      v := q('select listagg(grantee || '':'' || privilege, '','') within group (order by grantee) from dba_tab_privs
              where owner = ''BANK'' and table_name = ''CARDS'' and grantee <> ''BANK''');
      info('C04', 'PCI 7', 'who has object privileges on BANK.CARDS', nvl(v, 'nobody but the owner'));
    end;
  end if;
end;
/
exit
