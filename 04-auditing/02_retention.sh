#!/bin/bash
# Audit retention (PCI-DSS 10.5.1: 12 months kept, 3 months at hand) — archive first, purge only what was archived.
#   setup        encrypted tablespace AUDIT_TBS for the unified trail (new partitions), schema AUDIT_MGR (no password,
#                nobody logs in as it) with procedure AUDIT_ARCHIVE: writes the records older than 90 days since the
#                last archive to a CSV file, re-counts them in the trail, and only when the counts match moves the
#                last-archive timestamp. The procedure gets AUDIT_ADMIN/AUDIT_VIEWER through code-based access
#                control (roles granted to the procedure, not usable by anything else). Jobs: archive daily 01:00,
#                DBMS_AUDIT_MGMT purge job every 24 h with use_last_arch_timestamp (cannot delete unarchived records)
#   archive-now  run the archive job once (as its owner, not as SYS) and show the result
#   purge-now    one manual purge with use_last_arch_timestamp — same rule as the job
#   status       records by age, last-archive timestamp, jobs, archive files
# usage (from the host): ./02_retention.sh <db host> <PDB> setup | archive-now | purge-now | status
set -eu
H=${1:?db host} PDB=${2:?PDB} MODE=${3:?setup|archive-now|purge-now|status}
DIR=/u01/app/oracle/audit_archive/$(echo "$PDB" | tr A-Z a-z)
sql() { { echo "whenever sqlerror exit failure"; echo "set lines 200 pages 100 feedback on serveroutput on"; echo "alter session set container=$PDB;"; cat; echo "exit"; } \
          | ssh -o BatchMode=yes oracle@$H '. ~/.bash_profile >/dev/null 2>&1; sqlplus -s / as sysdba' 2>&1 | grep -v '^$'; }

case $MODE in
setup)
  ssh -o BatchMode=yes oracle@$H "mkdir -p $DIR && chmod 700 $DIR"
  sql <<SQL
create tablespace audit_tbs datafile size 64m autoextend on next 64m maxsize 4g
  encryption using 'AES256' encrypt;
exec dbms_audit_mgmt.set_audit_trail_location(dbms_audit_mgmt.audit_trail_unified, 'AUDIT_TBS')

create or replace directory audit_arch as '$DIR';
create user audit_mgr no authentication default tablespace audit_tbs quota 16m on audit_tbs;
grant create procedure, create job to audit_mgr;
grant audit_admin, audit_viewer to audit_mgr;
grant read, write on directory audit_arch to audit_mgr;
grant select on sys.dba_audit_mgmt_last_arch_ts to audit_mgr;

create table audit_mgr.archive_runs (run_ts timestamp default systimestamp, from_utc timestamp, to_utc timestamp,
                                     rows_out number, file_name varchar2(200));

create or replace procedure audit_mgr.audit_archive(p_keep_days number default 90) authid current_user is
  v_from timestamp; v_cut timestamp; n number := 0; n_check number; fname varchar2(200);
  f utl_file.file_type; c sys_refcursor;
  ts varchar2(40); u varchar2(128); act varchar2(64); os varchar2(128); obn varchar2(128); rc number;
  pol varchar2(4000); osu varchar2(128); uh varchar2(128); prg varchar2(128); txt varchar2(4000);
  function q(s varchar2) return varchar2 is begin return '"'||replace(s, '"', '""')||'"'; end;
begin
  execute immediate q'[select max(last_archive_ts) from sys.dba_audit_mgmt_last_arch_ts
                        where audit_trail = 'UNIFIED AUDIT TRAIL']' into v_from;
  v_from := nvl(v_from, timestamp '1970-01-01 00:00:00');
  v_cut  := cast(trunc(sys_extract_utc(systimestamp)) - p_keep_days as timestamp);
  if v_from >= v_cut then return; end if;
  fname := 'unified_'||to_char(v_from, 'yyyymmdd')||'_'||to_char(v_cut, 'yyyymmdd')||'.csv';
  f := utl_file.fopen('AUDIT_ARCH', fname, 'w', 32767);
  utl_file.put_line(f, 'event_timestamp_utc,dbusername,action_name,object_schema,object_name,return_code,'||
                       'unified_audit_policies,os_username,userhost,client_program_name,sql_text');
  open c for q'[select to_char(event_timestamp_utc, 'yyyy-mm-dd"T"hh24:mi:ss.ff6'), dbusername, action_name,
                       object_schema, object_name, return_code, unified_audit_policies, os_username, userhost,
                       client_program_name,
                       translate(dbms_lob.substr(sql_text, 3000, 1), chr(10)||chr(13), '  ')
                  from unified_audit_trail
                 where event_timestamp_utc >= :a and event_timestamp_utc < :b
                 order by event_timestamp_utc]' using v_from, v_cut;
  loop
    fetch c into ts, u, act, os, obn, rc, pol, osu, uh, prg, txt;
    exit when c%notfound;
    utl_file.put_line(f, ts||','||q(u)||','||q(act)||','||q(os)||','||q(obn)||','||rc||','||q(pol)||','||
                         q(osu)||','||q(uh)||','||q(prg)||','||q(txt));
    n := n + 1;
  end loop;
  close c; utl_file.fclose(f);
  execute immediate q'[select count(*) from unified_audit_trail
                        where event_timestamp_utc >= :a and event_timestamp_utc < :b]' into n_check using v_from, v_cut;
  if n_check <> n then
    raise_application_error(-20001, 'archive '||fname||': '||n||' rows written, '||n_check||' in the trail - not marked');
  end if;
  execute immediate 'begin dbms_audit_mgmt.set_last_archive_timestamp(dbms_audit_mgmt.audit_trail_unified, :t); end;'
    using v_cut;
  insert into audit_mgr.archive_runs (from_utc, to_utc, rows_out, file_name) values (v_from, v_cut, n, fname);
  commit;
end;
/
show errors procedure audit_mgr.audit_archive
grant audit_admin, audit_viewer to procedure audit_mgr.audit_archive;

begin
  dbms_scheduler.create_job(job_name => 'AUDIT_MGR.AUDIT_ARCHIVE_DAILY', job_type => 'STORED_PROCEDURE',
    job_action => 'AUDIT_MGR.AUDIT_ARCHIVE', repeat_interval => 'FREQ=DAILY;BYHOUR=1;BYMINUTE=0',
    -- the scheduler default time zone here is PST8PDT: without a start date '01:00' meant 16:00 local time
    start_date => to_timestamp_tz(to_char(trunc(sysdate) + 1, 'yyyy-mm-dd')||' 01:00 Asia/Ho_Chi_Minh', 'yyyy-mm-dd hh24:mi tzr'),
    enabled => true, comments => 'unified audit: archive records older than 90 days to CSV, then mark them');
  dbms_audit_mgmt.create_purge_job(audit_trail_type => dbms_audit_mgmt.audit_trail_unified,
    audit_trail_purge_interval => 24, audit_trail_purge_name => 'PURGE_UNIFIED_DAILY',
    use_last_arch_timestamp => true, container => dbms_audit_mgmt.container_current);
end;
/
select owner, job_name, enabled, repeat_interval from dba_scheduler_jobs
 where job_name in ('AUDIT_ARCHIVE_DAILY', 'PURGE_UNIFIED_DAILY');
SQL
  ;;
archive-now)
  sql <<'SQL'
exec dbms_scheduler.run_job('AUDIT_MGR.AUDIT_ARCHIVE_DAILY', use_current_session => false)
col additional_info for a90
select status, error#, additional_info from dba_scheduler_job_run_details
 where owner = 'AUDIT_MGR' and job_name = 'AUDIT_ARCHIVE_DAILY' order by log_date desc fetch first 1 row only;
select from_utc, to_utc, rows_out, file_name from audit_mgr.archive_runs order by run_ts;
SQL
  ssh -o BatchMode=yes oracle@$H "ls -l $DIR; for f in $DIR/*.csv; do echo \"\$(basename \$f): \$((\$(wc -l < \$f) - 1)) records\"; done"
  ;;
purge-now)
  sql <<'SQL'
exec dbms_audit_mgmt.clean_audit_trail(dbms_audit_mgmt.audit_trail_unified, use_last_arch_timestamp => true)
SQL
  ;;
status)
  sql <<'SQL'
with a as (select nvl(max(last_archive_ts), timestamp '1970-01-01 00:00:00') ts from dba_audit_mgmt_last_arch_ts
            where audit_trail = 'UNIFIED AUDIT TRAIL')
select case when t.event_timestamp_utc < a.ts then 'archived (purgeable)' else 'not archived' end state,
       count(*) records, min(t.event_timestamp_utc) oldest
  from unified_audit_trail t cross join a
 group by case when t.event_timestamp_utc < a.ts then 'archived (purgeable)' else 'not archived' end order by 1;
select audit_trail, last_archive_ts from dba_audit_mgmt_last_arch_ts;
select job_name, job_status, job_frequency from dba_audit_mgmt_cleanup_jobs;
select owner, job_name, enabled, state, to_char(next_run_date, 'yyyy-mm-dd hh24:mi tzr') next_run from dba_scheduler_jobs
 where job_name in ('AUDIT_ARCHIVE_DAILY', 'PURGE_UNIFIED_DAILY');
select parameter_name, parameter_value from dba_audit_mgmt_config_params
 where audit_trail = 'UNIFIED AUDIT TRAIL' and parameter_name like '%TABLESPACE%';
SQL
  ;;
esac
