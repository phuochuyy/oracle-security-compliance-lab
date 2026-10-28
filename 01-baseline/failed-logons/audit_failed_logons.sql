-- Failed logons from the unified audit trail, grouped by source. Run as SYSDBA in CDB$ROOT.
-- ORA_LOGON_FAILURES is enabled by default in 23ai, so these records exist without any setup.
set lines 220 pages 100
col dbusername for a10
col os_username for a10
col userhost for a16
col client_program_name for a36
select return_code, dbusername, os_username, userhost, client_program_name, count(*) n,
       to_char(min(event_timestamp), 'MM-DD HH24:MI') first_seen,
       to_char(max(event_timestamp), 'MM-DD HH24:MI') last_seen
  from unified_audit_trail
 where action_name = 'LOGON' and return_code <> 0
 group by return_code, dbusername, os_username, userhost, client_program_name
 order by n desc;
