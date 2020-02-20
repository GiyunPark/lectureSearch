# Search easier, Learn faster.

국내외 프로그래밍 영상을 모아서 보여주는 웹 애플리케이션입니다.

프로그래밍 입문자들이 어떤 분야를 배우려고 할 때 필요한 선지식, 해당 기술에 대한 로드맵 등을 추가하여 입문자들에게 도움이 될 수 있는 애플리케이션 개발을 목표로 하고 있습니다.

<br>

## 주요 구현 기능
<ul>
	<li>로그인 기능( Oauth2를 이용한 sns 로그인 및 spring scurity 를 이용한 로그인) </li>
	<li>게시판 ( 페이징 처리 등) </li>
	<li>검색 시스템 ( ElasticSearch, Nori analysis 를 활용한 형태소 분석 검색 ) </li>
	<li>관리자 페이지 구성 ( 회원 통계 및 랭킹 시스템 관리 ) </li>
</ul>
<br>

<h2>도구 버전</h2>
	<ul>
		<li> spring boot 2.2.0 </li>
		<li> spring boot elasticsearch 3.2.0 </li>
		<li> Elasticsearch 6.8.1 </li>
		<li> Kibana 6.8.1 </li>
	</ul>

<br>

## 회의록

<details>
<summary>미팅 1회차</summary>
<h2>프로젝트 미팅 1회차</h2>
장소 : 커피빈 (서울 강남구 테헤란로1길 29), 강남역 11번 출구 인근<br>
시간 :2019.09.18  오후 7시<br>
작성자 : <a href='https://github.com/GiyunPark'>박기윤</a><br>
<br>
<h2>회의 내용</h2>
<ol>
	<li>웹 사이트 주제 선정</li>
	<ul>
		<li>각자 아이디어 1~2개정도는 생각해서 모이면 좀더 원활히 진행 될거같습니다!</li>
	</ul>
	<li>모임 횟수 정하기</li>
	<ul>
		<li>자신이 원하는 정기 및 일반 모임 횟수(구체적인 시간까지)                예) 일반 스터디 월-금 9시부터 18시까지 희망, 정기 수요일 1회 등 </li>
	</ul>
	<li>개발 도구, 사용 언어 선정</li>
	<ul>
		<li>intelllj or eclispe, docker, mySQL, git, gitHub 등등..</li>
		<li>특히 intellj or eclispe 에대해서는 어떤것이 좋을지 생각해 오셨으면 합니다.!!</li>
	</ul>
	<li>기타 자신이 하고 싶은말 또는 바라는 것을 생각해오시면 얘기하는 시간을 갖을 생각입니다.</li>
</ol>
<br>
<h2>주제</h2>
<ul>
	<li>중고 경매 시스템</li>
	<li>날씨 api를 이용한 옷 추천</li>
	<li>쇼핑몰</li>
	<li>서점</li>
	<li>커플 가계부</li>
	<li>1인 크리에이터 영상 추천 플랫폼</li>
	<li>강의 추천 플랫폼 <b>*selected*</b></li>
	<ul>
		<li>예) 자바 관련 강의 검색 시 동영상을 가지고 있는 플랫폼 목록을 보여주고
플랫 폼 하위 목록으로 관련 강의 동영상 리스트를 띄움</li>
		<li>사용자가 직접 강의를 게시 할 수 있고 랭크 시스템을 통해 상위로 보내 노출</li>
		<li>기능</li>
		<ul>
			<li>회원가입 - 암호화방식(ssl, rsa) - oauth2</li>
			<li>관리자 - 플랫폼 관리 - 회원관리</li>
			<li>검색 – 필터링 – 강의리스트 출력(플랫폼 정보포함) - 사용자 </li>
			<li>게시 – 추천,랭크 – 수강후기</li>
			<li>FAQ-챗봇</li>
			<li>참고사이트 : <a href='https://www.justwatch.com/kr' target='_blank' class='url'>https://www.justwatch.com/kr</a></li>
		</ul>
	</ul>
</ul>
<br>
<h2>정기모임</h2>
<ul>
	<li>매주 목요일 (주1회)</li>
	<li>오전 10시</li>
	<li>장소 : 미정 (선릉역 디캠프 예상)</li>
</ul>
<br>
<h2>개발 도구</h2>
<ul>
	<li>인텔리제이 얼티메이트</li>
	<li>오라클</li>
	<li>docker</li>
</ul>
<br>
<h2>다음 주 정기 모임 과제( 자료 만들어서 배포 )</h2>
<ul>
	<li>도커에 대해서 (모영진)</li>
	<li>깃 사용법 (이동렬)</li>
	<li>자바 8 람다식 (박기윤) </li>
	<li>스프링 기본 개념 숙지 (박기윤)</li>
	<li>테스트코드가 왜 필요한가? (박기윤)</li>
	<li>주제에 맞게 적용할 css 템플릿 하나 찾아오기(전인원)</li>
	<li>기획서 작성하는 방법, 필요한 자료들 예)ERD, 클래스 다이어그램</li>
</ul>
<br>
<h2>개발환경(버전)</h2>
JDK1.8.202(SE 8)(2019년 1월 15일) 버전 이하 사용시 무료
<br>
<h2>19일 모임 – 개발환경 세팅</h2>
<ul>
	<li>도커 최신버젼</li>
	<li>인텔리제이 2019.02</li>
	<li>오라클db 18c</li>
	<li>자바 jre 1.8.0_202</li>
	<li>개발 방법론 정하기</li>
	<ul>
		<li>칸반보드</li>
		<li>스크럼보드</li>
		<li>애자일</li>
	</ul>
</ul>
</details>

<details>
<summary>미팅 2회차</summary>
모임 시간 :2019.09.19 10시 30분<br>
장소 : 선릉역 4번출구 디캠프 4층 커뮤니티룸<br>
작성자 : <a href='https://github.com/GiyunPark'>박기윤</a><br>
<br>
<h2>완료한 사항</h2>
<ul>
	<li>자바 버전 1.8.0_202로 통일</li>
	<li>팀 전원 intellij ultimate 버전 설치</li>
	<li>docker 설치</li>
	<ul>
		<li>mysql latest 버전으로 docker에 설치</li>
	</ul>
</ul>
<br>
<h2>회의내용</h2>
<h3>기능추가 사항</h3>
<ul>
	<li>위시리스트, 장바구니 기능</li>
	<li>무료, 유료 나누고 sort by까지</li>
</ul>
<br>
<h3>결정된 사항</h3>
<ul>
	<li>CSS template (MIT Licence 로서 무료로 사용가능)<br>
	<a href='https://demo.themewagon.com/preview/free-bootstrap-4-html5-real-estate-website-template-homeland' target='_blank' class='url'>https://demo.themewagon.com/preview/free-bootstrap-4-html5-real-estate-website-template-homeland</a></li>
	<li>애자일 방법론</li>
</ul>
<br>
<h2>기타사항</h2>
<p>2019 tech meet-up about block chain 강연 참여
장소：디캠프 6층</p>
<br>
<h2>역할분담</h2>
<ul>
  <li>회원가입 (<a href='https://github.com/youngjinmo'>모영진</a>)</li>
  <li>게시물　(<a href='https://github.com/ryeol37'>이동렬</a>)</li>
  <li>검색 (<a href='https://github.com/GiyunPark'>박기윤</a>)</li>
</ul>
</details>

<details>
<summary>미팅 3회차</summary>
모임 시간 :2019.09.26 10시 30분<br>
장소 : 선릉역 4번출구 디캠프 4층 커뮤니티룸<br>
작성자 : <a href='https://github.com/GiyunPark'>박기윤</a><br>
<br>
<h2>회의내용</h2>
<ul>
	<li><p>mybatis/ JPA 결정하기</p>
	<ul>
		<li>JPA &lt;-- 결정</li>
	</ul>
	<li>기획서에 대해 클래스 다이어그램</li>
	<li>기능 명세서</li>
	<ul>
		<li>(디자인 패턴 등 아키텍처를 생각하며 개발하는 것이 중요)</li>
	</ul>
	<li>일정표 작성하기</li>
<ul>
<br>
</details>

<details>
<summary>미팅 4회차</summary>
모임 시간 :2019.10.03 10시<br>
장소 :  강남역 12번 출구 인근 스타벅스<br>
작성자 : <a href='https://github.com/GiyunPark'>박기윤</a><br>
<br>
	<h2>회의내용</h2>
	<ul>
		<li>공부 해오고 설명들은 내용 중 더 깊이 파고들 내용 정하기</li>
	</ul>
<br>
	<h2>활동 내용</h2>
	<ul>
		<li>각자 공부해온 내용 설명 및 듣기</li>
	</ul>
<br>
	<h2>다음 주 까지 할일</h2>
	<ul>
		<li>Bena Component 차이?</li>
		<li>엘라스틱 서치란? </li>
		<li>왜 JPA가 객체 지향인가?</li>
	</ul>
<br>
</details>

<details>
<summary>미팅 5회차</summary>
모임 시간 :2019.10.09 10시<br>
장소 :  강남역 12번 출구 인근 스타벅스<br>
작성자 : <a href='https://github.com/GiyunPark'>박기윤</a><br>
<br>
	<h2>회의내용</h2>
	<ul>
		<li>동적 사이트 구축을 위해 필요한 언어 결정하기 ex) JSP, thymeleaf
		<li>회의 결과 : thymeleaf 로 결정</li>
		<li>이유 : spring boo2 에서 권장하는 언어이고 러닝타임이 길지 않을 것 이라는 의견</li>
	</ul>
<br>
	<h2>다음 주 까지 할 일</h2>
	<ul>
		<li>개인이 맡은 프로젝트 코드 개발 및 코드 리뷰 준비</li>
	<ul>
<br>
	<h2>활동 내용</h2>
	<ul>
		<li>docker elasticsearch, docker kibana 팀 전원 동일 환경 구성</li>
		<li>elasticsearch, kibana, spring boot2를 연동하여 CRUD 동작 테스트</li>
	</ul>
<br>
</details>
<br>

## 실습 방법

1. Docker 컨테이너(<a href="https://hub.docker.com/repository/docker/youngjindev/lecturesearch_aws" target="_blank">Docker Hub</a>)를 실행한다.

~~~
$ docker start lectureSearch
~~~



2. bash 모드로 컨테이너 내부 진입하기

~~~
$ docker exec -it lectureSearch bash
~~~



3. 계정 전환하기

~~~
/# sudo - devandy
~~~



4. AWS 인스턴스(ec2-user)에 SSH 진입하기

~~~
ssh aws-lectureSearch
~~~



![](https://lh3.googleusercontent.com/g3gythLbQvNqh1DJ6gQzRucPwYQw2Sfm9jU8sCR_fOwDR91lEFpdD2zOoscPocSzFTx63lSKV8AuF-07Gc1VVvbkuLALMnSOGJLh48MFwF7s4ZwVTikVzFAFH--ool-g5Ko58Q_1IznNG_R_-v6z7y5ILdToKNuTORER51xEpIqLsEbCLWeAEBquJZ9V8TQHd7eJhr6B4wOlIFQBgk1e2p4SHFOABkP8GnMsDm4LnRL4cd97vGCibHKq0PcSxpHpkNBFJzxCQZPDKjdOt5ZxNtFD8oDpQYkISU9eYnRfrF4mfdm6yDCjebx0pZe6I6kuIEudmCx6CDFuiFTP7bab6KJSYl485y0VMxFwZH0V0Urhv_LdKEcFEseq5TScTz287zIDAujl7GFR_AvCQ-ZvVHLUYwF8q6W8F1rwhQGgyN-A5j8QfaVU1dBA1jSv4Ay6lIgNhUkHImOgFi2uFsdw-pPVSTXzgn-ulPJvpcPko1OLOkVv4fSAKjI0k-orTdowrCu4ACWJgoBRacnlwvJiQUT-r5zT4ak0498oAc_SWJbwMT1htqFimaXUnCsgg1CxeMKuXQJYI0tktKPs-R7--GSZ8RKFIjpIQSgzm0ZVLTq9iNnYyIPt_xaHfjZJ2yQtG2zrWSKNnZwtAXPal2ysJHODlR4W3rcTPtSo3N87R419ItMqih0IoGaQHlAgaCl8O-2HeMmgKVMK-9-QHFEomYeHwIT27I5G9vDqxSS7oIxyiINDcg=w1440-h814-no)

