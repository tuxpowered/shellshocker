#!/bin/sh
#
# Testing for shellshock issues.
# Based on code for internal testing.
#

PATH=/usr/bin:/bin
VERSION="`echo $Revision: 1.33 $ | tr -cd 0-9.`"
DEFAULT_SHL=/bin/bash
SHELLS=
KEEP=false
DIR=""
SKIP6277=false
case `uname -s` in
   MINGW*|CYGWIN*)        SKIP6277=true ;;
esac

while [ $# -gt 0 ] ; do
    case "$1" in
        -a|-all|--all|all)
            for d in `echo $PATH | tr : '\n'` ; do
                [ -x "$d/sh"   ] && SHELLS="$SHELLS $d/sh"
                [ -x "$d/bash" ] && SHELLS="$SHELLS $d/bash"
            done
            ;;
        -d|--d|-dir|--dir|-directory|--directory)
            DIR="$2"
            shift ;;
        -h|--h|-help|--help)
            echo "Usage: $0 [ options ] [ <path_to_shell> ... ]"
            echo ""
            echo "Options:"
            echo "--dir <DIR>  Use <DIR> as the working directory (default is to"
            echo "             attempt to create a random temp dir)"
            echo "--help       Output this usage message"
            echo "--keep       Do not remove temp files when done testing"
            echo "--skip       Don't run the test for CVE-2014-6277"
            echo "--version    Show the version of this script"
            exit 0 ;;
        -k|--k|-keep|--keep)
            KEEP=true ;;
        -s|--s|-skip|--skip)
            SKIP6277=true ;;
        -v|--v|-version|--version)
            echo "Version: $VERSION"
            exit 0 ;;
        *)
            SHELLS="$SHELLS $1" ;;
    esac
    shift
done
[ "x$SHELLS" = "x" ] && SHELLS=$DEFAULT_SHL

TEMPDIR=""
if [ "x$DIR" = "x" ]; then
    MKTEMP=true
    if [ -x /bin/mktemp ] ; then
        tmpfile=`/bin/mktemp -c -p BrOkEn 2>&1`
        if echo "$tmpfile" | grep tmp/BrOkEn > /dev/null 2>&1 ; then
            echo "Warning! You have an old mktemp that cannot securely create"
            echo "temporary directories.  Falling back to non-secure method..."
            rm -f $tmpfile
            MKTEMP=false
        fi
    else
        echo "Warning! /bin/mktemp not available"
        echo "You're vulnerable to /tmp collision attacks (such as symlink races)!"
        MKTEMP=false
    fi
    if $MKTEMP ; then
        TEMPDIR=`/bin/mktemp -d /tmp/.shellshock_test.XXXXXX` || exit 1
    else
        TEMPDIR=/tmp/.shellshock_test.$$
        if [ -d $TEMPDIR ] ; then
            echo "temp dir collision! Remove /tmp/.shellshock* directories and try again"
        fi
        mkdir -p $TEMPDIR || exit 1
    fi
    DIR=$TEMPDIR
fi
cd $DIR
# Capture stderr. Used to identify segfaults
exec 2> stderr
trap "" SEGV

echo test | grep -q test > greptest.out 2> greptest.err
if [ -s greptest.err ]; then
    GREPQ=grepq
else
    GREPQ="grep -q"
fi

grepq() {
    grep "$@" > grep.out 2> grep.err
    return $?
}

run_tests() {
    SHELL=$SHL; export SHELL

    # CVE-2014-6271 - The original shellshock bug.
    # Test if code after the function definition gets run
    # (arbitrary code execution)
    cp stderr pre-test.err
    ( env var='() { ignore this;}; echo vulnerable' $SHL -c /bin/true ) > CVE-2014-6271.out 2>&1
    comm -13 pre-test.err stderr > CVE-2014-6271.err

    # CVE-2014-7169 - The second bug found
    # Test for parsing error with quoting and redirection that can
    # cause any command to be run (although you can't pass args to it)
    # (so you can run "halt", or "/sbin/halt", but not "halt -n")
    cp stderr pre-test.err
    ( env var='() {(a)=>\' $SHL -c "echo date"; cat echo ) > CVE-2014-7169.out 2>&1
    comm -13 pre-test.err stderr > CVE-2014-7169.err

    # CVE-2014-7186 - Overflow redirection array
    # Test if the parser has a limit on redirections, but does not
    # check if the limit is exceeded
    # This check can hang on really old bash versions, so run it
    # in the background and kill it, if it's still running after 10 secs
    cp stderr pre-test.err
    ( $SHL -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo "vulnerable" ) >> CVE-2014-7186.out 2>&1 &
    pid=$!
    sleep 1
    if kill -0 $pid > /dev/null 2>&1 ; then
        sleep 9
        if kill -15 $pid > /dev/null 2>&1 ; then
            echo vulnerable >> CVE-2014-7186.out
        fi
    fi
    comm -13 pre-test.err stderr > CVE-2014-7186.err

    # CVE-2014-7187 - An off-by-one bug in loop nesting
    # Most versions of bash have a limit on the how deeply loops
    # can be nested, but the check for that limit checks the
    # value before it is incremented, while the incremented value
    # is what is actually used, creating an off-by-one error.
    # The canonical test provided by Florian Weimer, who found
    # the bug, would be:
    # (for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | $SHL || echo "vulnerable"
    # but older versions of bash (and non-bash shells) don't
    # understand the {x..y} syntax, so I made this alternative:
    NUMS=""
    for a in 0 1 ; do
        for b in 0 1 2 3 4 5 6 7 8 9 ; do
            for c in 0 1 2 3 4 5 6 7 8 9 ; do
                NUMS="$NUMS $a$b$c"
            done
        done
    done
    cp stderr pre-test.err
    ( ( for x in $NUMS; do echo "for x$x in ; do :"; done; for x in $NUMS; do echo done; done ) | $SHL || echo "vulnerable" ) > CVE-2014-7187.out 2>&1
    comm -13 pre-test.err stderr > CVE-2014-7187.err

    if ! $SKIP6277 ; then
        # CVE-2014-6277 - Use of uninitialized memory
        # Test for a redirection structure that isn't fully
        # initialized resulting in dereferencing an invalid
        # pointer (so a segfault occurs)
        #  See http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
        cp stderr pre-test.err
        ( env var='() { x() { _; }; x() { _; } <<a; }' $SHL -c : ) > CVE-2014-6277.out 2>&1
        comm -13 pre-test.err stderr > CVE-2014-6277.err
    fi

    # CVE-2014-6278 - Another arbitrary code execution bug
    # This is another parser bug that executes any code given
    # Tests for the bug in redirecting to nested variable substitutions
    #  See http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
    cp stderr pre-test.err
    ( env var='() { _; } >_[$($())] { echo vulnerable; }' $SHL -c : ) > CVE-2014-6278.out 2>&1
    comm -13 pre-test.err stderr > CVE-2014-6278.err

    # THIS IS THE MOST IMPORTANT CHECK
    # Check to see if the shell has been modified to keep arbitrary
    # environment variables from being passed to the parser.
    # This means the shell has been hardened to prevent this whole
    # class of bugs from being exploitable.  This makes all of the
    # above vulnerabilities, and any more parsing bugs yet to be
    # discovered, not applicable to environment variable values
    # and therefore, not exploitable (at least via shellshock-style
    # attack vectors)
    # See https://lists.gnu.org/archive/html/bug-bash/2014-09/msg00238.html
    cp stderr pre-test.err
    $SHL -c "export functest=ftvar gunctest='() {'; functest() { echo func:functest ;}; export -f functest; $SHL -c 'echo var:functest=\$functest; echo var:gunctest=\"\$gunctest\"; functest; env | grep ^[fg]unctest= | sed s/^/env:/'" > any_parser_bug.out 2>&1
    comm -13 pre-test.err stderr > any_parser_bug.err
}

collect_cve_results() {
    VULN=false
    if $GREPQ vulnerable CVE-2014-6271.out ; then
        echo "CVE-2014-6271: VULNERABLE"
        VULN=true
    else
        echo "CVE-2014-6271: not vulnerable"
    fi

    if $SKIP6277 ; then
        echo "CVE-2014-6277: Skipped   - test does not work on Cygwin/MinGW"
    else
        # Note: check the .err file, not .out, for a segfault
        if $GREPQ -i seg CVE-2014-6277.err ; then
            echo "CVE-2014-6277: VULNERABLE"
            VULN=true
        else
            echo "CVE-2014-6277: not vulnerable"
        fi
    fi

    if $GREPQ vulnerable CVE-2014-6278.out ; then
        echo "CVE-2014-6278: VULNERABLE"
        VULN=true
    else
        echo "CVE-2014-6278: not vulnerable"
    fi

    if $GREPQ '[0-9]:[0-5][0-9]:[0-5][0-9]' CVE-2014-7169.out ; then
        echo "CVE-2014-7169: VULNERABLE"
        VULN=true
    else
        echo "CVE-2014-7169: not vulnerable"
    fi

    if $GREPQ vulnerable CVE-2014-7186.out ; then
        echo "CVE-2014-7186: VULNERABLE"
        VULN=true
    else
        echo "CVE-2014-7186: not vulnerable"
    fi

    if $GREPQ vulnerable CVE-2014-7187.out ; then
        echo "CVE-2014-7187: VULNERABLE"
        VULN=true
    else
        echo "CVE-2014-7187: not vulnerable"
    fi
}

check_shell_type() {
    if env -i $SHL -c 'set TESTVAR=csh; echo $TESTVAR' | $GREPQ csh; then
        echo csh ; return
    fi
    # Check for sash-style shells
    $SHL > functest.out 2>&1 << EOF
        functest() { echo hello; }
        functest
EOF
    if ! $GREPQ hello functest.out ; then
        echo sash ; return
    fi
    if ! $SHL -c "func() { echo hello; }; export -f func > /dev/null 2>&1; env" | $GREPQ func ; then
        # Pretty much any Bourne derivative not derived from bash
        echo sh ; return
    fi
    echo bash
}

echo "shellshock_test.sh version $VERSION"
EXITCODE=0
for SHL in $SHELLS; do
    rm -f *.out *.err echo
    if [ ! -x $SHL ]; then
        echo "Can't execute shell $SHL"
        continue
    fi

    echo "Evaluating $SHL..."
    SKIPTESTS=true
    type=`check_shell_type`

    case "$type" in
        csh)      echo "This shell is a csh derivative." ;;
        sash)     echo "This shell does not fully support functions" ;;
        sh)       echo "This shell does not support exporting functions to the environment." ;;
        bash)     SKIPTESTS=false ;;
    esac

    FUTUREPROOF=true
    if $SKIPTESTS; then
        echo "It is NOT vulnerable to shellshock attacks. Skipping tests..."
        VULN=false
    else
        echo "Running tests..."
        run_tests

        echo "Tests completed. Determining results..."
        collect_cve_results

        FIX=none
        VARS_CORRECT=false
        FUNC_FIX=""
        if $GREPQ '^var:functest=ftvar$' any_parser_bug.out && $GREPQ '^var:gunctest=() {$' any_parser_bug.out ; then
            VARS_CORRECT=true
        fi
        if $GREPQ '^func:functest$' any_parser_bug.out ; then
            FUNC_FIX="It does not pass arbitrary environment variables to the parser"
        fi
        if $GREPQ '.*functest.*[Cc]ommand not found' any_parser_bug.out ; then
            FUNC_FIX="Exporting functions to the environment is disabled"
        fi
        if $VARS_CORRECT && [ "$FUNC_FIX" != "none" ] ; then
            echo "This shell should be immune to shellshock attack via any parser bugs"
            echo "$FUNC_FIX"
            if $VULN; then
                echo "(any cases of 'VULNERABLE' above are likely still parser bugs,"
                echo "but they are therefore not exploitable security issues)"
                VULN=false
            fi
        else
            echo "VULNERABLE TO ANY OTHER PARSER BUGS"
            FUTUREPROOF=false
        fi
    fi

    echo ""
    if $VULN ; then
        echo "Overall status: VULNERABLE"
        EXITCODE=1
    else
        if $FUTUREPROOF ; then
            echo "Overall status: Not vulnerable"
        else
            echo "Overall status: Not vulnerable to current exploits"
        fi
    fi
    echo ""
done

if ! $KEEP ; then
    if [ "x$TEMPDIR" != "x" ]; then
        cd /
        rm -rf $DIR
    fi
fi

exit $EXITCODE
