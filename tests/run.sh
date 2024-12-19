#!/bin/sh

TESTDIR=$(dirname $0)/
SRCDIR=src/
PWD=$(pwd)
DEFAULTPORT=8080
LOGFILE=/tmp/ouistiti.log
. ./.config

CONTINUE=0
GCOV=0
ALL=0
NOERROR=0
while [ -n "$1" ]; do
case $1 in
	-D)
		DEBUG=1
		;;
	-C)
		CONTINUE=1
		;;
	-GCOV)
		GCOV=1
		;;
	-V)
		VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --log-file=/tmp/ouistiti.valgrind"
		#VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --vgdb=yes"
		VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --child-silent-after-fork=yes"
		VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --trace-children=yes"
		VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --track-origins=yes"
		#VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --leak-check=full"
		#VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --show-leak-kinds=all"
		VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --show-error-list=yes"
		VALGRIND_OPTIONS=$VALGRIND_OPTIONS" --run-libc-freeres=yes"
		echo VALGRIND OPTIONS: $VALGRIND_OPTIONS
		ENV="valgrind $VALGRIND_OPTIONS"
		;;
	-I)
		INFO=1
		;;
	-A)
		ALL=1
		TESTS=$(find $TESTDIR -maxdepth 1 -name "test*[0-9]" | sort)
		;;
	-N)
		NOERROR=1
		;;
	-P)
		DEFAULTPORT=$1
		shift
		;;
	-h)
		printf "$0 <-I> <-D> <-C> <-GCOV> test/test[09]*\n"
		printf "\t-D    run test on an existing server\n"
		printf "\t-A    run all tests\n"
		printf "\t-N    continue running after error\n"
		printf "\t-I    display information about test and the response\n"
		printf "\t-C    leave ouistiti running for the next test\n"
		printf "\t-GCOV run lcov to display the code coverage\n"
		exit 1
		;;
	*)
		TESTS=$1
		;;
esac
shift
done

echo $TESTS

TMPRESPONSE=/tmp/ouistiti.test

AWK=awk
SED=sed
WC=wc
CURL=curl
WGET=wget
#USER=$(ls -l $0 | ${AWK} '{print $3}')
USER=$(ps -p $$ -o user --no-headers)
TESTCLIENT="./host/utils/testclient"
LD_LIBRARY_PATH=${SRCDIR}:$TESTDIR../libhttpserver/src/:$TESTDIR../libhttpserver/src/httpserver/:$TESTDIR../utils/

export LD_LIBRARY_PATH

if [ -z "$INFO" ]; then
CURLOUT="-o /dev/null"
fi

TESTERROR=""

rm -f ${TESTDIR}run.pid

config () {
	CONFIG=$1

	cp ${TESTDIR}conf/${CONFIG}.in ${TESTDIR}conf/${CONFIG}
	${SED} -i "s,\%PWD\%,$PWD,g" ${TESTDIR}conf/${CONFIG}
	${SED} -i "s,\%USER\%,$USER,g" ${TESTDIR}conf/${CONFIG}
	${SED} -i "s,\%LOGFILE\%,$LOGFILE,g" ${TESTDIR}conf/${CONFIG}

}

start () {
	TARGET=$1
	CONFIG=$2

	ARGUMENTS=""
	if [ "$VTHREAD" != "y" ]; then
		ARGUMENTS=" -s 1"
	fi
	#ARGUMENTS=$ARGUMENTS" -s 1"
	ARGUMENTS=$ARGUMENTS" -f ${TESTDIR}conf/${CONFIG}"
	ARGUMENTS=$ARGUMENTS" -P ${TESTDEFAULTPORT}"
	ARGUMENTS=$ARGUMENTS" -M ./staging:./src"
	if [ -n "$INFO" ]; then
		echo ${SRCDIR}${TARGET} ${ARGUMENTS}
		echo "******************************"
		cat ${TESTDIR}conf/${CONFIG}
	fi
	echo "${ENV} ${SRCDIR}${TARGET} ${ARGUMENTS}"
	${ENV} ${SRCDIR}${TARGET} ${ARGUMENTS} &
	PID=$!
	echo "${TARGET} started with pid ${PID}"
	echo "config ${TESTDIR}conf/${CONFIG}"
	sleep 1
}

stop () {
	TARGET=$1

	if [ -n "$PID" ]; then
		kill $PID
		sleep 1
		kill -9 $PID
	else
		killall $(echo $TARGET | ${AWK} '{print $1}')
		sleep 1
		killall -9 $(echo $TARGET | ${AWK} '{print $1}')
	fi
}

test () {
	TEST=$1

	unset CMDREQUEST
	unset FILEDATA
	unset PREPARE
	unset CURLPARAM
	unset TESTREQUEST
	unset TESTRESPONSE
	unset TESTCODE
	unset TESTHEADERLEN
	unset TESTCONTENTLEN
	unset TESTOPTION
	unset ASYNC_PID
	unset PREPARE_ASYNC
	unset PREPARE
	unset PID
	TESTDEFAULTPORT=$DEFAULTPORT
	TESTRESPONSE=$(basename ${TEST})_rs.txt
	if [ -e ${TESTDIR}$(basename ${TEST})_rq.txt ]; then
		TESTREQUEST=$(basename ${TEST})_rq.txt
	fi
	DISABLED=0
	. $TEST
	TESTOPTION="${TESTOPTION} -p ${TESTDEFAULTPORT}"

	echo
	echo "******************************"
	echo $TEST
	echo $DESC
	if [ $DISABLED -eq 1 ]; then
		return
	fi

	if [ -n "$FILEDATA" ]; then
		cp ${TESTDIR}htdocs/${FILE}.in ${TESTDIR}htdocs/${FILE}
		${SED} -i "s/\%FILEDATA\%/$(echo $FILEDATA | ${SED} 's/\//\\\//g')/g" ${TESTDIR}htdocs/${FILE}
		TESTCONTENTLEN=$(cat ${TESTDIR}htdocs/${FILE} | ${WC} -c)
	fi

	config $CONFIG
	rm -f $TMPRESPONSE

	if [ -n "$PREPARE_ASYNC" ]; then
		$PREPARE_ASYNC &
		ASYNC_PID=$!
		sleep 1
	fi

	if [ -n "$PREPARE" ]; then
		eval $PREPARE
	fi

	if [ $CONTINUE -eq 0 ] && [ -z $DEBUG ]; then
		start "$TARGET" $CONFIG
	fi

	echo "----"
	if [ -n "$CURLPARAM" ]; then
		if [ -n "$INFO" ]; then
			echo "get $CURLPARAM"
			echo "----"
		fi
		$CURL $CURLOUT -f -s -S $CURLPARAM > $TMPRESPONSE
	fi
	if [ -n "$WGETURL" ]; then
		if [ -n "$INFO" ]; then
			echo "get $WGETURL"
			echo "----"
		fi
		$WGET --no-check-certificate -S -q -O - $WGETURL 2> $TMPRESPONSE.tmp
		#$WGET --no-check-certificate -S -O - $WGETURL
		cat $TMPRESPONSE.tmp | sed 's/^  //g' > $TMPRESPONSE
	fi
	for REQUEST in ${TESTREQUEST} ; do
		if [ -n "$REQUEST" ]; then
			if [ -n "$INFO" ]; then
				cat ${TESTDIR}$REQUEST
				echo "----"
			fi
			echo cat ${TESTDIR}$REQUEST' |' $TESTCLIENT $TESTOPTION
			cat ${TESTDIR}$REQUEST | $TESTCLIENT $TESTOPTION >> $TMPRESPONSE
		fi
	done
	if [ -n "$CMDREQUEST" ]; then
		if [ -n "$INFO" ]; then
			$CMDREQUEST
			echo "----"
		fi
		$CMDREQUEST | $TESTCLIENT $TESTOPTION > $TMPRESPONSE
	fi
	ERR=0
	if [ -n "$INFO" ]; then
		cat $TMPRESPONSE
		echo $TEST
		echo $DESC
		rescode=$TESTCODE
		resheaderlen=$TESTHEADERLEN
		rescontentlen=$TESTCONTENTLEN
	else
		if [ -e ${TMPRESPONSE} -a ${TESTRESPONSE} != "none" ]; then
			diff -aZ ${TMPRESPONSE} ${TESTDIR}${TESTRESPONSE} | grep -a '^>.*$'
			if [ ! $? -eq 1 ]; then
				ERR=4
			fi
		fi
		rescode=$(cat $TMPRESPONSE | ${AWK} '/^HTTP\/1\.[0,1] .* .*/{print $2}' )
		resheaderlen=$TESTHEADERLEN
		rescontentlen=$TESTCONTENTLEN
		#resheaderlen=$(echo $result | ${AWK} -F= 't$0 == t {print $0}' | wc -c)
		#rescontentlen=$(echo $result | ${AWK} -F= 't$0 != t {print $0}' | wc -c)
	fi
	if [ -n "$TESTCODE"  ]; then
		if [ "x$rescode" = "x" ]; then
			rescode="none"
		fi
		echo $rescode | grep $TESTCODE > /dev/null
		if [ $? -eq 1 ]; then
			echo "result code error $rescode instead $TESTCODE"
			ERR=1
		fi
	fi
	if [ -n "$TESTHEADERLEN" -a x$resheaderlen != x$TESTHEADERLEN ]; then
		echo "header error received $resheaderlen instead $TESTHEADERLEN"
		ERR=2
	fi
	if [ -n "$TESTCONTENTLEN" -a x$rescontentlen != x$TESTCONTENTLEN ]; then
		echo "content error received $rescontentlen instead $TESTCONTENTLEN"
		ERR=3
	fi
	if [ ! $ERR -eq 0 ]; then
		echo "$TEST quits on error"
		stop $TARGET
		cat $LOGFILE
		if [ $NOERROR -eq 1 ]; then
			TESTERROR="${TESTERROR} $TEST"
		else
			exit 1
		fi
	else
		echo "$TEST completed"
		echo "status        : $TESTCODE"
		if [ x"$TESTHEADERLEN" != x ]; then
			echo "header  length: $TESTHEADERLEN"
		fi
		if [ x"$TESTCONTENTLEN" != x ]; then
			echo "content length: $TESTCONTENTLEN"
		fi
	fi
	if [ $CONTINUE -eq 0 ]; then
		stop $TARGET
	fi
	if [ x$ASYNC_PID != x ]; then
		kill $ASYNC_PID
	fi
}

TARGET="ouistiti"
stop ${TARGET}
for TEST in ${TESTS}
do
	test $TEST
done

if [ ${ALL} -eq 1 ]; then
	ARGUMENTS=" -M ./src:./staging"
	${SRCDIR}${TARGET} ${ARGUMENTS} -h
	${SRCDIR}${TARGET} ${ARGUMENTS} -V
	${SRCDIR}${TARGET} ${ARGUMENTS} -C -f ${TESTDIR}conf/test1.conf
	${SRCDIR}${TARGET} ${ARGUMENTS} -W ${TESTDIR} -f ${TESTDIR}conf/test.conf -p $TMPRESPONSE.pid -D
	sleep 1
	$WGET --no-check-certificate -S -q -O - http://127.0.0.1:8080/index.html 2> $TMPRESPONSE.tmp
	sleep 1
	${SRCDIR}${TARGET} ${ARGUMENTS} -p $TMPRESPONSE.pid -K
fi
if [ ${GCOV} -eq 1 ]; then
	make DEBUG=y gcov
	lcov --directory . -c -o gcov.info
	genhtml -o ./gcov_report -t "couverture de code des tests" gcov.info
	firefox ./gcov_report/index.html
fi
if [ -n "$TESTERROR" ]; then
	echo $TESTERROR
	exit 1
fi
