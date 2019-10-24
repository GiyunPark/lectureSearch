## Login 구현시 SpringBoot 버전 에러 발생시 해결한 케이스



### 1. OAuth2 의존성 문제

**Problems**

예제 코드를 통해 Security를 설정하고 있었는데, 예제 코드와 현재 내가 사용중인 SpringBoot가 버전이 달라지면서 클래스나 애노테이션을 못불러오는 경우가 발생했다.

**How to Solve**

SpringBoot2의 의존성(dependency)를 변경했다.

```gradle
repositories{
   mavenCentral()
   maven{ url 'https://repo.spring.io/snapshot'}
}

dependencies {
   compile 'org.springframework.security.oauth.boot:spring-security-oauth2-autoconfigure:2.0.1.BUILD-SNAPSHOT'
}
```

<br>

### 2. `WebMvcConfigurerAdapter` 사용불가

**Problem**

부트애플리케이션 클래스()에서 상속받는 `WebMvcConfigurerAdapter` 를 사용하려고 하니 사용할 수 없었다.

![](http://www.mediafire.com/convkey/58df/2vo72o7ytq3lb72zg.jpg)

**Why?**

SpringBoot2가 Spring Framework5를 사용한다고 하는데, Spring Framework5에서는 `webMvcConfigurerAdapter` 대신 `WebMvcConfigurer`를 사용한다고 한다.

**How to solve?**

![](http://www.mediafire.com/convkey/936c/g85hf4ueu8k5km9zg.jpg)

이 문제는 인터페이스 `WebMvcConfigurer`  를 상속받는것으로 해결했다.