#!/bin/bash

echo "------------------------"
echo "| Step 1: Start dirsrv |"
echo "------------------------"

/usr/lib/dirsrv/dscontainer -r &

echo "------------------------------------"
echo "| Step 2: Wait for dirsrv to start |"
echo "------------------------------------"

# until ldapwhoami -H ldap://localhost:3389 -x | grep -q "anonymous";
# until dsctl --json slapd-localhost healthcheck | grep -q "[]";
until /usr/lib/dirsrv/dscontainer -H;
do
  echo $(date) " Still waiting for dirsrv to start..."
  sleep 5
done

# WARNING: healthcheck above returns even if dirsrv isn't quite ready if once.sh wasn't already run
# so if you haven't pre-run dscontainer you should sleep right here or otherwise wait for "🎉 Instance setup complete"
#sleep 5

echo "---------------------"
echo "| Step 3: Configure |"
echo "---------------------"
# Run custom scripts provided by the user
# usage: run_custom_scripts PATH
#    ie: run_custom_scripts /container-entrypoint-initdb.d
# This runs *.sh, *.ldif files
# Inspired by: https://github.com/gvenzl/oci-oracle-xe/blob/0cedd27ab04771789f1425639434d33940935f6c/container-entrypoint.sh#L208
function run_custom_scripts {

  SCRIPTS_ROOT="${1}";

  # Check whether parameter has been passed on
  if [ -z "${SCRIPTS_ROOT}" ]; then
    echo "No SCRIPTS_ROOT passed on, no scripts will be run.";
    return;
  fi;

  # Execute custom provided files (only if directory exists and has files in it)
  if [ -d "${SCRIPTS_ROOT}" ] && [ -n "$(ls -A "${SCRIPTS_ROOT}")" ]; then

    echo -e "\nCONTAINER: Executing user defined scripts..."

    run_custom_scripts_recursive ${SCRIPTS_ROOT}

    echo -e "CONTAINER: DONE: Executing user defined scripts.\n"

  fi;
}

# This recursive function traverses through sub directories by calling itself with them
# usage: run_custom_scripts_recursive PATH
#    ie: run_custom_scripts_recursive /container-entrypoint-initdb.d/001_subdir
# This runs *.sh, *.ldif files and traverses in sub directories
function run_custom_scripts_recursive {
  local f
  for f in "${1}"/*; do
    case "${f}" in
      *.sh)
        if [ -x "${f}" ]; then
                    echo -e "\nCONTAINER: running ${f} ...";     "${f}";     echo "CONTAINER: DONE: running ${f}"
        else
                    echo -e "\nCONTAINER: sourcing ${f} ...";    . "${f}"    echo "CONTAINER: DONE: sourcing ${f}"
        fi;
        ;;

      *.ldif)        echo -e "\nCONTAINER: running ${f} ..."; echo "exit" | ldapmodify -D "cn=Directory Manager" -w ${DS_DM_PASSWORD} -H ldap://localhost:3389 -x -f "${f}"; echo "CONTAINER: DONE: running ${f}"
        ;;

      *)
        if [ -d "${f}" ]; then
                    echo -e "\nCONTAINER: descending into ${f} ...";    run_custom_scripts_recursive "${f}";    echo "CONTAINER: DONE: descending into ${f}"
        else
                    echo -e "\nCONTAINER: ignoring ${f}"
        fi;
        ;;
    esac
    echo "";
  done
}

if [ ! -f /setup-complete ]; then
echo -e "Running setup scripts"
run_custom_scripts "/container-entrypoint-initdb.d"
touch /setup-complete
else
echo -e "Setup already run; skipping"
fi

echo "----------"
echo "| READY! |"
echo "----------"

sleep infinity
