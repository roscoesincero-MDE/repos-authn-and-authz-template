#!/bin/sh
# Builds a disposable template database with a throwaway bootstrap verifier and runs 010-080. Usage: Build-Upstream.sh <db>
DB=$1
cd "$(dirname "$0")"
PHC=$2
sqlcmd -S MDE-55TT2J4 -E -C -b -Q "IF DB_ID(N'$DB') IS NOT NULL BEGIN ALTER DATABASE [$DB] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$DB]; END" > /dev/null
powershell -NoProfile -ExecutionPolicy Bypass -File ../Install-TemplateDatabase.ps1 -DatabaseName $DB -BootstrapAdminVerifierPhc "$PHC" > ../_logs/${DB}_install.txt 2>&1
echo "Install rc=$? FAILED=$(grep -c FAILED ../_logs/${DB}_install.txt)"
for f in [0-9]*.sql; do
  case $f in
    070_*) for v in VARIANT1 VARIANT2 VARIANT3; do
             sqlcmd -S MDE-55TT2J4 -d $DB -E -C -I -b -v DbName=$DB -v Variant=$v -v Seed=s$$$v -i $f > ../_logs/test_${DB}_${f%.sql}_$v.log 2>&1
             echo "$f $v rc=$?"; done ;;
    *) sqlcmd -S MDE-55TT2J4 -d $DB -E -C -I -b -v DbName=$DB -v Seed=s$$ -i $f > ../_logs/test_${DB}_${f%.sql}.log 2>&1
       echo "$f rc=$?" ;;
  esac
done
