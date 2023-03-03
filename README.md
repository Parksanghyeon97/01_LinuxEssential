Linux Essential 과정 정리

Linux 기초 관리자 과정

########################
제 01장. 리눅스 소개
########################

자격증
* 민간 자격증
* 국가 자격증
   리눅스 마스터 1급/2급
   네트워크 관리사 1급/2급
   
   정보처리기사
* 국제 공인 자격증
   AWS SA
   RedHat RHCSA/RHCE
   LPIC

[참고] 복제된 운영체제에서 변경 사항
* 호스트 이름
   # hostnamectl
   # hostnamectl set-hostname server2.example.com
* IP 설정
   # nm-connection-editor
   # nmcli connection up ens160


########################
제 02장 리눅스 설치
########################


########################
제 03장 리눅스 환경 설정
########################

리눅스의 선수지식
* Runlevel == Target
   runlevel 3 == multi-user.target
   runlevel 5 == graphical.target

   # systemctl isolate multi-user.target|graphical.target
   # systemctl set-default multi-user.target|graphical.target
* 서비스 기동
   # systemctl enable|disable firewalld
   # systemctl start|stop firewalld
* 제어 문자(Control Character)
   <CTRL + C>, <CTRL + D>

Runlevel 0 = Power Off
Runlevel 6 = reboot

* 도움말과 암호변경
	man CMD //manual

		#man ls 가장 많이 사용됨
		#man -k calendar (키워드 검색)
		#man -f passwd (목록 볼때)
		#man -s 5 passwd (섹션 번호 지정)
		
		[ 참고 ] 명렁어 옵션 확인
		# ls --help // 간략하게
		# man ls // 자세하게

	passwd CMD //password
		# passwd fedora

########################
제 04장 리눅스 기본 정보 확인
########################

시스템 기본 정보 확인
	uname CMD
		# uname -a
		# cat /etc/redhat-release (# ls /etc/*release*)
	date CMD
		# date 08301300 (8월30일13시) =데모버전 계속쓰기
		# date +%m%d

		[실무예] NTP 서버에 시간 동기화
		# gedit , vi /etc/chrony.conf
		server time.bora.net iburst
		# systemctl stop chronyd
		# systemctl start chronyd

	cal CMD //달력 출력

########################
제 05장 파일 및 디렉토리 관리
########################

디렉토리 이동 관련 명령어

	[ 참고 ] 파일시스템 기본 구조
	# man 7 hier

	pwd CMD
		[ 참고 ] PS1 변수 ($HOME/.bashrc)
		# export  PS1='[\u@\h \w]\$ `  // W ->w (워킹디렉토리)
	cd CMD
		경로(Part)
		* 상대경로(Relative Path) # cd dir1  // 현재기준 시작 위아래
		* 절대경로(Absolute Path) # cd /dir1 // 최상위 기준으로 시작

		[ 참고 ] 자신의 홈디렉토리 이동
		# cd
		# cd ~
		# cd $HOME

		[ 참고 ] 지정된 사용자 홈디렉토리 이동
		# cd ~fedora

		[ 실무예 ] 이전 디렉토리로 이동하기
		# cd -

		[ 실무예 ] 옆에 있는 디렉토리로 이동하기
		# cd ../dir2

디렉토리 관리 명령어
	ls CMD(확인)
		# ls -l dir1 (long ~ 길게 설명)
		# ls -ld dir1
		OPTIONS : -l(길게) , -d(디렉토리 속성), -R (체계적인), -a(all .까지), -i (inode번호), -h(인간적으로 2000k -> 2M), -t(시간별로), -r(꺼꾸로)

		[ 참고 ] alias
		(선언) # alias ls='ls -l | grep "^-"'
		(확인) # alias
		(해제) # unalias ls

		[ 실무예 ] 실무에서 많이 사용되는 ls CMD
		# cd /Log_dir
		# ls -altr (가장밑에 있는게 가장 최근)

	mkdir CMD(생성)

		# mkdir -p dir1/dir2 (한번에 생성) // p = parents 아빠 없으면 생성 있으면 그냥흘러감

	rmdir CMD(삭제)
		# rm -rf dir1 << 요거를 기억하자

파일 관리 명령어
	touch CMD
		# touch -t 08301300 file1
	cp CMD
		# cp file1 file2
		# cp file1 dir1
		# cp -r dir1 dir2 ( dir2가 있는경우 없는경우)
		OPTIONS: -r (디렉토리 복사할때), -i(인간적으로 물어봄) ,-f(강제), -p(퍼미션 복사)

		[ 실무예 ] 설정 파일을 백업하는 경우
		# cp -p httpd.conf httpd.conf.orig // 백업 -p 옵션 중요
		# cp -a /stc /stc.orig // ex. 폴더 (소스코드가 들어가있는경우) // a 옵션안에 p옵션이 들어가있음

		[ 실무예 ] 로그 파일 비우기
		# cp / dev/null file.log
		# cat / dev/null > file.log
		# > file.log //요거 기억
		
	mv CMD
		# mv file1 file2
		# mv file1 dir1
		# mv dir1 dir2 (dir2 가 있거나 없거나)
		OPTIONS: -i(인터렉티브), -f(force)

		[ 참고 ] 와일드 캐릭터(Wild Character)
		* ? {} []
	rm CMD
		# rm -rf dir1

		[ 실무예 ] rm 명령어로 지운 파일 복원하기
		( TUI ) extundelete CMD
		( GUI ) TestDisk 툴


파일 내용 확인 명령어
	cat CMD
		# cat -n file1 // number
		# cat file1 file2 > file3
	more CMD
		# CMD | more
		# ps -ef | more
		# cat /etc/services | more
		# netstat -an | more
		# systemctl list-unit-files // 요즘것들은 내장됨

	| (파이프 명령어) 
	앞에 명령어 출력 결과를 뒤에 명령어 입력으로 인식

	gedit ~/.bashrc // alias 생성
	. ~/.bashrc // 적용

	head CMD
		# alias pps='ps -ef | head -1 ; ps -ef | grep $1 '
		# alias nstate='netstate -antup | head -2 ; netstate -antup | grep $1'
	tail CMD

		# top
		# tail -f /var/log/messages

		# tail -f /var/log/messages | egrep -i '(warn|fail|error|crit|alert|emerg)'
		# tail -f /var/log/messages /var/log/secure 
		
		[ 참고 ] telnet 서비스 기동하기
		# yum install telnet telnet-server //설치
		# systemctl start telnet.socket (# systemctl enable --now telnet.socket) // 현재시작
		# systemctl enable telnet.socket // 부팅시에도 적용
		# systemctl enable --now telnet.socket // 현재 + 부팅


기타 관리용 명령어

	wc CMD
		[ 참고 ] 데이터 수집(Data Gathering)
		# ps -ef | tail -n +2 | wc -l
		# cat /etc/passwd | wc -l
		# rpm -qa | wc -l
		# df -k / | tail -l | awk '{print %5}'
		# cat /var/log/messages | grep 'Jan 19' | grep 'Started Telnet Server' | wc -l

	su CMD
		# su oracle    // 현재상태 그대로 넘어가기
		# su - oracle // oracle에서 처음 로그인한것처럼 넘어가기 

	sudo CMD(/etc/sudoers, /etc/sudoers.d/*)
		# sudo CMD
		# sudo -l (목록확인)
		# sudo -i (관리자로 스위칭)

	id CMD //명령어정도만
	groups CMD // 명령어정도만

	last CMD(/var/log/wtmp) 내용을 출력하는것 (ex 로그인 로그아웃)
		# last -i
		# last -f /var/log/wtmp.20230128

	lastlog(/var/log/lastlog)
		# 사용자가 서버에 마지막 로그인한 시간

	lastb CMD(/var/log/btmp)
		# 서버에 접근할때 실패한 기록들 , 사용자의 로그인 실패 기록 

	who CMD(/var/run/utmp)
		# 내 서버에 누가 들어와있나
	w CMD // 모니터링 느낌
		[ 참고 ] 모니터링 구문
		while true
		do
			echo "-----`date`-----"
			CMD
			sleep 2
		done

		[ 참고 ] watch CMD // 모니터링 느낌

	exit CMD



########################
제 06장 파일 종류
########################

파일 종류

* 일반 파일(Regular File)
* 디렉토리 파일(Directory File)
* 링크 파일(Link File)
	* 하드 링크 파일(Hard Link File)
		# ln file1 file2
	* 심볼릭 링크 파일(Symbolic Link File)
		# ln -s file1 file2
* 장치 파일(Device)
	* 블록 장치 파일(Block Device File)
	* 캐릭터 장치 파일(Character Device File)


########################
제 07장 파일 속성 관리
########################

chown CMD
	# chown -R fedora:fedora /home/fedora
chgrp CMD
chmod CMD
	퍼미션 변경
	* 심볼릭 모드( Symbolic Mode ) # chmod u+x file1
	* 옥탈 모드( Octal Mode ) # chmod 755 file1
	파일 & 디렉토리 퍼미션
	* 파일( r / w / x )
	* 디렉토리( r(ls -l CMD) / w(생성/삭제) / x(cd CMD) )

	퍼미션 적용 순서
	* UID check -> GIDs check -> other 
	umask CMD(002 -> 022 -> 027) 실무에선 바꾸지 말아라
	* (관리자) /etc/bashrc
	* (사용자) $HOME/.bashrc

########################
제 08장 VI / VIM 편집기
########################

VI 편집기 모드
* 명령 모드 (Command/Edit Mode)
	이동, 삭제, 실행취소/재실행, 복사, ...
* 입력 모드 (Insert / Input Mode)
	i, a, o/O
* 최하위행 모드 (Last Line/Ex Mode)
	저장&나가기, 검색, 검색&바꾸기, 복사/이동하기

VI 편집기 환경파일
* $HOME/.vimrc
	set nu
	set ai
	set ts=4 sw=4


########################
제 09장 사용자와 통신할 때 사용하는 명령어
########################

mail/mailx CMD // 메일전송
	# mailx -s ' [	OK	] server1' admin@example.com < /root/report.txt
wall CMD
	# wall < /etc/MESS/work.txt

	[참고] 긴급 작업 절차
	# touch /etc/nologin
	# wall < /etc/MESS/work.txt
	...
	# fuser -cu /home
	# fuser -ck /home
	작업 진행
	# rm -f /etc/nologin



###############################
제 10장 관리자가 알아두면 유용한 명령어
###############################

cmp/diff CMD
	[실무예] 설정 파일 비교
	# diff httpd.conf httpd.conf.OLD

	[실무예] 디렉토리 마이그레이션 종료 후 비교
	# find /was1 | wc -l ; find /was2 | wc -l
	# diff -r /was1 /was2

sort CMD
	# CMD | sort -k 3
	# CMD | sort -k 3 -n
	# CMD | sort -k 3 -nr

	[ 실무예 ] 파일/파일시스템 사용량 점검
	# df -k
	# du -sk /var
	# cd /var ; du -sk * | sort -nr | more

file CMD
	# file *

###############################
제 11장 검색 관련 명령어
###############################

grep CMD
	grep OPTIONS PATTERN file1
	* OPTIONS: -i, -l, -v, -r, -n, --color, -A
	* PATTERN: *  .  ^root root$ [abc] [a-c] [^a]//a 만 아니면 되는 한글자
	
	CMD | grep root
	# cat /etc/passwd | grep root 
	# rpm -qa | grep httpd 
	# ps -ef | grep rsyslogd  //프로세서 전체 리스트 
	# systemctl list-unit-files | grep ssh 
	# netstat -antup | grep :22 
	
	[ 실무예 ] 로그 파일 점검 스크립트
	# alias chklog='cat $1 | egrep -i --color "(warn|error|fail|crit|alert|emerg)"'
	# vi /root/bin/chklog.sh

find CMD
	# find / -name core -type [f|d]    (# find / -name "*oracle*" -type f)
	# find / -user user01 -group class1 
	# find / -mtime [-7|7|+7] 
	# find / -perm [-755|755] 
	# find / -size [-300M|300M|+300M]
	# find / -name core -type f -exec rm -f {    } \;

	[ 실무예 ] 오래된 로그 파일 삭제 ( find CMD + rm CMD + crontab CMD)
	# find /Log_Dir -name "*.log" -type f -mtime +30 -exec rm -f {} \;

	[ 실무예 ] 갑자기 파일시스템 풀(full) 난 경우(-mtime)
	df CMD + du CMD + find CMD + lsof CMD
	# df -k
	# du -sk /var
	# cd /var ; du -sk * | sort -nr more
	#

###############################
제 12장 압축과 아카이빙
###############################

압축(Compress)
	gzip/ginzip CMD
		# gzip file1
		# gunzip -c file1.gz
		# gunzip file1.gz
	bzip2/bunzip2 CMD
		# bzip2 file1
		# bunzip2 -c file1.bz2
		# bunzip2 file1.bz2
	xz/unxz CMD
		# xz file1
		# unxz -c file1.xz
		# unxz file1.xz
아카이빙(Archive)
	tar CMD
	# tar cvf file.tar file1 file2 file3
	# tar tvf file.tar
	# tar xvf file.tar
압축 + 아카이빙
	tar CMD
	(tar CMD + gzip CMD)
	# tar cvzf file.tar.gz file1 file2 file3
	# tar tvzf file.tar.gz
	# tar xvzf file.tar.gz
	
	(tar CMD + bzip2.CMD)
	# tar cvjf file.tar.bz2 file1 file2 file3
	# tar tvjf file.tar.bz2
	# tar xvjf file.tar.bz2

	(tar CMD + xz CMD)
	# tar cvJf file.tar.xz file1 file2 file3
	# tar tvJf file.tar.xz
	# tar xvJf file.tar.xz	
	
	jar CMD
	# jar cvf file.jar file1 file2 file3
	# jar tvf file.jar
	# jar xvf file.jar
	
	zip/unzip CMD
	# zip file.zip file1 file2
	# unzip -l file.zip
	# unzip file.zip
	
###############################
제 13장 배시쉘의 특성
###############################

리다이렉션(Redirection)
	fd
	-------------------------
	0 stdin(keyboard)
	1 stdout(Screen)
	2 stderr(Screen)
	-------------------------

	입력 리다이렉션(stdin) # wall < /etc/MESS/work.txt
	출력 리다이렉션(stdout) # ls -l > lsfile.txt
	에러 리다이렉션(stderr) # ls -l /test /nodir > list.txt 2>&1    //에러2번도 1번으로 보내라
	
	[ 실무예 ] 스크립트 로그 파일 생성
	# ./script.sh > script.log 2>&1 
	
	[ 실무예 ] 출력 내용이 긴 명령 수행시 출력 화면 분석
	# ./configure > config.log 2>&1
	
	[ 실무예 ] 일반사용자가 명령 수행시 에러메시지를 지우는 경우
	$ find / -name core -type f 2>/dev/null
	
	
파이프(Pipe)
	# CMD | more
	# CMD | grep inetd
	# CMD | CMD | ...
	
	[ 실무예 ] 모니터링 구문 + 데이터 수집(CMD | tee -a httpd.cnt)
	while true
	do	
		ps -ef | grep httpd | wc -l | tee -a httpd.cnt
		sleep 2
	done
	
	[ 실무예 ] 여러 터미널 화면을 공유하는 경우
	# script -a /dev/null | tee /dev/pts/1 | tee /dev/pts/2
	
	
배시쉘 기능(Shell Function)
	# set -o //전체 리스트 확인
	# set -o vi // 기능 ON
	# set +o vi // 기능 OFF
	
	# set -o ignoreeof <CTRL + D > 방지 기능 ON
	# set +o ignoreeof <CTRL + D > 방지 기능 OFF

	<TAB>
		* 파일이름 자동 완성 기능
		* 디렉토리 안에 파일 목록 보기

	<↑>
		* 이전에 수행된 명령어를 편집해서 사용하기
		* 이전에 수행된 명령어를 확장해서 사용하기
		* 확인 + 명령수행 + 확인
		
	< Copy & Paste >

변수(Variable)
	변수의 종류
	* 지역변수(Local Variable) # VAR=5
	* 환경변수(Environment Variable) # export VAR=5
	* 특수변수(Special Variable) $$(PID), $?(바로이전 명령어 return), $!(바로이전 background PID)
	$0 , $1, $2, $#, $*
	
	변수 선언 방법
		# export VAR=5
		# echo $VAR
		# unset VAR
	
	export 의미
	시스템/쉘 환경변수(set/env)
		PS1 변수: export PS1='[\u@\h \w]\$ ' ($HOME/.bashrc)
		PS2 변수
		PATH 변수 : 명령어를 검색할 디렉토리를 선언할 때 사용
			export PATH=$PATH:/root/scripts ($HOME/.bash_profile)
			HISTTIMEFORMAT 변수 : export HISTTIMEFORMAT="%F %T    " (/etc/profile)
		HOME 변수
		PWD 변수
		LOGNAME 변수
		USER 변수
		UID 변수
		TERM 변수 : export TERM=vt100
		LANG 변수 : export LANG=ko_KR.UTF-8|en_US.UTF-8
		
		
쉘 메타캐릭터(shell Metacharacter)
	'' "" `` \ ;

명령어 히스토리(Command History)
	HISTSIZE=512
	HISTFILE=$HOME/.bash_history
	HISTFILESIZE=512
	
엘리어스(Alias)
	# alias cp='cp -i'
	# alias 
	# unalias cp

환경파일(Environment Files)
	/etc/profile 
	#모든 사용자에게 적용됨
	
	~/.bash_profile  ($HOME/.bash_profile)
	
	~/.bashrc ($HOME/.bashrc)

###############################
제 14장 프로세스관리
###############################

프로세스 정보
	/proc/PID/*		#여기에 남겨진다.
	PID(Process Identification) : 프로세스가 시작할 때 할당받는 프로세스 식별번호
	PPID(Parent Process Identification) : 부모 프로세스 식별번호 (서브 프로세스를 실행시킨 프로세스)
프로세스 관리
	프로세스 관리1
		프로세스 실행
			fg[foreground]) # gedit
			bg[background]) # gedit &
		프로세스 확인
			# ps -ef[모든리스트][full name] | grep sshd
				/* e : 모든 프로세스 리스트를 출력한다.
				   f : 모든 정보를 출력한다. (full format) */
			
			# ps aux | grep sshd
				/* a : 다른 사용자의 프로세스 상태도 표시
				   x : 화면에 보이지 않는 프로세스까지 모두 표시
				   u : 프로세스를 사용한 사용자와 실행 시간까지 표시 */
		프로세스 종료
			# kill -1|-2|-9|-15 PID PID
			// -15 = 시그널 번호 생략 [정상 종료]
			// -9 = [강제 종료]
			// -2 = <CTRL + C >
			// -1 = [재시작] 설정 적용할때 많이 씀
			
			
			[참고] killall CMD, pkill CMD
			[참고] kill vs killall/pkill   차이점은? PID,프로세서이름
			
	프로세스(잡, Job) 관리2
		잡(Job)? 실행중인 프로그램을 프로세스라고 하고, 프로세스를 하나의 잡(Job)이라고 한다.
		
		잡 실행
			fg[foreground]) # gedit
			bg[background]) # gedit &
		잡 확인
			# jobs
			
			# fg %1 
			# bg %1
			< CTRL + Z > 일시정지
		잡 종료
			# kill %1
			
프로세스 모니터링 [굉장히 중요한 부분, 명령어 출력 결과 해석]
	top CMD
		# top
		# top -u wasuser
		
	[참고] 모니터링 툴 
	*top/htop 	: CPU/MEM
	*iotop 		: DISK I/O
	*iftop		: Network I/O
	*atop 		: data gathering(데이터 수집) 
	*gnome-system-monitor
	
	
	lsof CMD
		# lsof
			# lsof /usr/sbin/sshd  //데몬의 이름
			# lsof /tmp
			# lsof /etc/passwd
		# lsof -c sshd
			# lsof /usr/sbin/sshd
			# lsof -c sshd
		# lsof -p PID
		# lsof -i
	pmap CMD
		# pmap CMD
	
	pstree CMD
		# pstree
		# pstree user01
		# pstree -alup PID
	nice/renice CMD
		[실무예] 백업 스크립트/데이터수집 스크립트 실행할 때
		# ./backup.sh &     <- x
		# nice ./backup.sh % (보통 -> 낮음)
		
		[실무예] CPU 부하가 높은 프로세스가 존재하는 경우
		# renice -n 10 PID  (보통 -> 낮음)

###############################
제 15장 원격접속과 파일전송
###############################

파일전송
	scp CMD
		# scp file1 server2:/tmp/file2         (나 -> 상대)
		# scp server2:/tmp/file2 /test/file1   (상대쪽에서 -> 나로 가져올때)
		# scp -r dir1 server2:/tmp              (디렉토리 복사)
	sftp CMD
	
원격접속
	ssh CMD
		# ssh server2
		# ssh server2 CMD
		
		[참고] Public Key Authentication
		# ssh-keygen									//키를 만들고
		# ssh-copy-id -i id_rsa.pub root@server2		//공개키를 보내라
	sftp CMD
	
★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆★☆

Notepad


MAC? 
IP address? 호스트 구분하는 번호 (집)
Port address? 서비스 구분하는 번호 (엄마,아빠,나) 
* 0 ~ 65535
* 0 ~ 1023 : 잘 알려진 서비스를 위해 할당하는 포트 번호 ( Well - Known Port )
	22: SSH
	23: Telnet
	25: SMTP
	53: DNS
	80: HTTP
	110: POP3
	123: NTP
	143: IMAP4
	
Well-Known Port 의 데몬들은 데몬을 기동할 때 관리자 권한이 필요하다.
