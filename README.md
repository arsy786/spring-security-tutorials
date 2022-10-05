# spring-security-tutorials
This project is a guide to learning Spring Security.

## Table of Contents
[1. Introduction to Spring Security](#1-introduction-to-spring-security)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[1.1 What is it?](#11-what-is-it)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[1.2 The 5 SS Concepts](#12-the-5-ss-concepts)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[1.3 Adding SS to SB app](#13-adding-ss-to-sb-app)
<br>
[2. Authentication](#2-authentication)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[2.1 What is it?](#21-what-is-it)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[2.2 How to configure SS Authentication](#22-how-to-configure-ss-authentication)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[2.3 Different Types of Authentication and How SS Authentication works](#23-different-types-of-authentication-and-how-ss-authentication-works)
<br>
[3. Authorization](#3-authorization)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[3.1 What is it?](#31-what-is-it)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[3.2 How to configure SS Authorization](#32-how-to-configure-ss-authorization)
<br>
[4. Database Authentication](#4-database-authentication)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[4.1 JDBC](#41-jdbc)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[4.2 JPA](#42-jpa)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[4.3 LDAP Server](#43-ldap-server)
<br>
[5. JWT](#5-jwt)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[5.1 What is it?](#51-what-is-it)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[5.2 Method 1 - Filter-based JWT (No OAuth)](#52-method-1---filter-based-jwt-no-oauth)
<br>
[6. OAuth](#6-oauth)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[6.1 What is it?](#61-what-is-it)
<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[6.2 Method 1 - OAuth2 JWT ](#62-method-2---oauth2-jwt)

## 1. Introduction to Spring Security

### 1.1 What is it?
API security is a critical component in production ready applications, this is because businesses use APIs to connect services and to transfer data, and so an unsecured API can lead to a myriad of problems such as data breaches. 

Spring Security is a powerful and highly customizable authentication and access-control framework. It is the de-facto standard for securing Spring-based applications.

Spring Security is a framework that focuses on providing both authentication and authorization to Java applications. Like all Spring projects, the real power of Spring Security is found in how easily it can be extended to meet custom requirements.

Source and more info: [spring.io/projects/spring-security](https://spring.io/projects/spring-security)

### 1.2 The 5 SS Concepts

1. Authentication - Who is the user?
2. Authorization - Are they allowed to do this?
3. Principal - Currently logged-in user/account
4. (Granted) Authority - Permissions/access (fine-grained)
5. Role - Group of authorities (coarse-grained)

Source and more info: [Five Spring Security Concepts](https://www.youtube.com/watch?v=I0poT4UxFxE&list=PLqq-6Pq4lTTYTEooakHchTGglSvkZAjnE&index=2)

### 1.3 Adding SS to SB app
- Add spring-boot-starter-security dependency to pom.xml.
- The default behaviour of SS once added to SB project:
1. Adds mandatory authentication for URLs
2. Adds login form
3. Handles login error
4. Creates a user (user) & sets a default password (generated in console)

Can configure the user and password in application.properties as follows:
``` properties
spring.security.user.name=foo
spring.security.user.password=pass 
```
NOTE: You should not configure the user/pwd in this location in production/real project. This is done for demonstration purposes only.

Source and more info: [Adding Spring Security to new Spring Boot project](https://www.youtube.com/watch?v=PhG5p_yv0zs&list=PLqq-6Pq4lTTYTEooakHchTGglSvkZAjnE&index=3)

## 2. Authentication
NOTE: Since version 5.7.0-M2, Spring deprecates the use of WebSecurityConfigureAdapter and suggests creating configurations without it.

### 2.1 What is it?
Used to validate whether a user is utilising an application by giving proper credentials. Authentication is the process of determining a principal's identity.

### 2.2 How to configure SS Authentication

- Spring Security automatically secures all HTTP endpoints with “basic” (and/or "form") authentication.
- This implementation example will be of storing users in memory, and having SS authenticate and verify against them.

With WebSecurityConfigurerAdapter:
``` java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void oonfigure(AuthenticationManagerBuilder auth) throws Exception {
    
        auth.inMemoryAuthentication()
            .withUser("user")
            .password("pass")
            .roles("USER")
            .and()
            .withUser("admin")
            .password("pass")
            .roles("ADMIN")
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}
```
- @EnableWebSecurity annotation tells Spring Security that this class is a Web Security configuration. (Another way to do this, is via application/method level security).
- WebSecurityConfigurerAdapter is extended here as it contains the methods that SS uses by default, and they can be overridden for our own custom implementation.
- Method chaining utilised here to make code/configuration more readable.
- .inMemoryAuthentication() only used for learning/example purposes!
- .roles required here for Role-based authorization (covered in next section).
- PasswordEncoder allows us to set a password encoder. It is required as you must NOT save plain text string passwords. Always deal with hashed passwords.

NOTE: For this example, the NoOpPasswordEncoder method does not do anything, you should NOT DO THIS in production app and instead use an actual encryption method (such as BCrypt).

Without WebSecurityConfigurerAdapter:
``` java
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public InMemoryUserDetailsManager userDetailsManager() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();
				
		UserDetails admin = User.withDefaultPasswordEncoder()
				.username("admin")
				.password("password")
				.roles("ADMIN")
				.build();

		return new InMemoryUserDetailsManager(user, admin);
	}
}
```

Source and more info: [How to configure Spring Security Authentication](https://www.youtube.com/watch?v=iyXne7dIn7U&list=PLqq-6Pq4lTTYTEooakHchTGglSvkZAjnE&index=4)

### 2.3 Different Types of Authentication and How SS Authentication works

Form Auth

- Form Authentication: Uses standard HTML form fields to pass the username and password values to the server via a POST request. 
- The server validates the credentials provided and creates a ‘session’ tied to a unique token stored in a cookie and passed between the client and the server on each HTTP request. If the cookie is invalid or the user is logged out, the server then usually redirects to a login page.
- It is a programmatic method of authentication used to mitigate the fact that each request has to be authenticated in Basic Auth.
- In most cases, Form-based Auth is used to authenticate a web browser based client and an API.

Basic Auth

- Basic Authentication: Uses an HTTP header in order to provide the username and password when making a request to a server. The header field itself looks like the following: **Authorization: Basic Base64-encoded(username:password)**

- The credentials are the base64 encoding (without encryption) of the username and password joined by a single colon.
- Base64 encodes binary data as values that can only be interpreted as text in textual media, and is free of any special characters and/or control characters, so that the data will be preserved across textual media as well.
- Basic Auth DOES NOT use cookies, hence there is no concept of a session or logging out a user, thus each request has to carry that header in order to be authenticated.
- In most cases, Basic Auth is used for authentication between API’s.
 
Both Basic Auth and Form-based Auth are considered to be on the weak end of the security strength spectrum unless used with some external secure system such as TLS.

NOTE: It is STRONGLY advised to use HTTPS when choosing Basic Auth or Form-based Auth to secure your systems!

[How Spring Security Authentication works](https://www.youtube.com/watch?v=caCJAJC41Rk&list=PLqq-6Pq4lTTYTEooakHchTGglSvkZAjnE&index=7)

![Spring Security Flow](SS-flow.png)
![Spring Security Flow 2](ss-authentication-flow.png)
![Spring Security Config](sb-ss-config.png)


## 3. Authorization
NOTE: Since version 5.7.0-M2, Spring deprecates the use of WebSecurityConfigureAdapter and suggests creating configurations without it.

### 3.1 What is it?
Authorization is a process by which a server determines if the client has permission to use a resource or access a file. It's an access control mechanism that determines whether or not a principal can conduct a task.

### 3.2 How to configure SS Authorization
- In SS, all API endpoints need authentication. What we want however, is different endpoints having different access requirements.
- In this example, given a Controller with different endpoints, we can enable/disable access to these API's depending on who the logged in user is.


HomeController:
``` java
@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return("Welcome");
    }

    @GetMapping("/user")
    public String user() {
        return("Welcome User");
    }
    
    @GetMapping("/")
    public String admin() {
        return("Welcome Admin");
    }

}
```

We want:

| API | Roles allowed to access it |
| ----------- | ----------- |
| **/** | All (unauthenticated) |
| **/user** | USER and ADMIN |
| **/admin** | ADMIN |

- To do this, need to use HttpSecurity. This object lets us configure paths and their access restrictions.

With WebSecurityConfigurerAdapter:
``` java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    
        auth.inMemoryAuthentication()
            .withUser("user")
            .password("pass")
            .roles("USER")
            .and()
            .withUser("admin")
            .password("pass")
            .roles("ADMIN")
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
    
        http.authorizeRequests()
            .antMatchers("/admin").hasRole("ADMIN")
            .antMatchers("/user").hasAnyRole("USER", "ADMIN")
            .antMatchers("/").permitAll()
            .and().formLogin();
    }

}
```
- If you have many endpoints with the same path and authorization requirement, can use /** to iclude all paths at the current level, as well as those nested below this.
- .hasRole() if endpoint only allows 1 specific role.
- .hasAnyRole() if endpoint allows multiple role access.
- .permitAll() if endpoint allows any (or no) role.
- .and() to end chaining
- .formLogin() to set authentication method as form-based.

NOTE: the order of .antMatchers is important. It must go from most restrictive to least restrictive!
<br>
NOTE: SS creates a /logout endpoint by default to allow you to end sessions.

Without WebSecurityConfigurerAdapter:
``` java
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
		    .csrf(csrf -> csrf.disable())
		    .authorizeRequests(auth -> {
		        auth.antMatchers("/admin").hasRole("ADMIN");
		        auth.antMatchers("/user").hasAnyRole("USER", "ADMIN");
		        auth.antMatchers("/").permitAll();
		    })
		    .httpBasic(Customizer.withDefaults());

		return http.build();
	}

}
```

- .httpBasic(Customizer.withDefaults()) will enable Http Basic Authentication for your application with some "reasonable" defaults. It uses base64 encoding for a valid username/password combination.
- We are telling Spring to authenticate the request using the values passed by the Authorization request header. If the request is not authenticated you will get a returned status of 401  and a error message of Unauthorized.

Source and more info: [How to configure Spring Security Authorization](https://www.youtube.com/watch?v=payxWrmF_0k&list=PLqq-6Pq4lTTYTEooakHchTGglSvkZAjnE&index=5)

## 4. Database Authentication
Spring Security provides support for username/password based authentication from a functioning Database layer connection.

### 4.1 JDBC

1. Create User tables and test data in schema.sql and data.sql respectively

- JDBC has a default schema in the format: id, username, password, role, enabled.
- If you are using the above default schema, you DO NOT need to add a custom schema.sql, and can simply use .withDefaultSchema() method in Step 4 (Configure JDBC Authentication details).
- If you have a custom schema that differs from the default, to implement the changes, you must add schema.sql AND modify the SQL queries in Step 4.
- In this example, we will add a custom schema that purposefully follows the default schema format. And we will purposefully add the extra SQL queries. Despite this technically being redundant, this is being carried out so the code below will still be of use in cases where custom schemas are in effect (as adjustments can be easily applied).

schema.sql:
``` roomsql
CREATE TABLE users (
  username VARCHAR(50) NOT NULL,
  password VARCHAR(100) NOT NULL,
  enabled TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (username)
);
  
CREATE TABLE authorities (
  username VARCHAR(50) NOT NULL,
  authority VARCHAR(50) NOT NULL,
  FOREIGN KEY (username) REFERENCES users(username)
);
```

data.sql:
``` roomsql
INSERT INTO users (username, password, enabled)
  values ('user',
    '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.AQubh4a',
    true);

INSERT INTO users (username, password, enabled)
  values ('admin',
    '$2a$10$8.UnVuG9HHgffUDAlk8qfOuVGkqRzgVymGe07xd00DMxs.AQubh4a',
    true);

INSERT INTO authorities (username, authority)
  values ('user', 'ROLE_USER');

INSERT INTO authorities (username, authority)
  values ('admin', 'ROLE_USER');
```

2. Configure Data Source properties in application.properties

- Specify database connection information in the application.properties file.
- Update the URL, username and password according to your MySQL (or other) database.

application.properties:
``` properties
spring.datasource.url=jdbc:mysql://localhost:3306/testdb
spring.datasource.username=root
spring.datasource.password=password
```

3. Add dependencies to pom.xml

- To use Spring Security APIs for the project and to use JDBC with Spring Boot and MySQL:

pom.xml:
``` xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <scope>runtime</scope>
</dependency>
```

4. Configure JDBC Authentication details
- To use Spring Security with form-based authentication and JDBC:

SecurityConfig.java:
``` java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
 
    @Autowired
    private DataSource dataSource;
     
    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().passwordEncoder(new BCryptPasswordEncoder())
            .dataSource(dataSource)
            .usersByUsernameQuery("select username, password, enabled "
                    + "from users "
                    + "where username = ?")
            .authoritiesByUsernameQuery("select username, authority "
                    + "from authorities "
                    + "where username = ?")
        ;
    }
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin().permitAll()
            .and()
            .logout().permitAll();     
    }
}
```

- DataSource reads DB connection info from applications.properties file.
- For JDBC authentication, we need to specify a password encoder, data source and two SQL statements: the first one selects a user based on username, and the second one selects role of the user.
- And to configure form-based authentication, we override the configure(HttpSecurity) method. Here, we specify that all requests must be authenticated, meaning the users must login to use the application. The default login form provided by Spring Security is used.
- You can also configure HttpSecurity here to add authorization and make use of Roles/Authorities from DB, but for this example it was not implemented.

NOTE: If using default schema, .usersByUsernameQuery and .authoritiesByUsernameQuery is not required. Although default schema has been used in this example, these two methods have been added still, so you can easily adapt the code if the schema does become custom. 

Source and more info: [How to setup JDBC authentication with Spring Security from scratch](https://www.youtube.com/watch?v=LKvrFltAgCQ&list=PLqq-6Pq4lTTYTEooakHchTGglSvkZAjnE&index=7)

### 4.2 JPA
- JDBC and LDAP come out of the box as Authentication providers for Spring Security. JPA however does not.
- Therefore, to implement JPA Authentication requires the implementation of UserDetailsService.

![Spring Security JPA Authentication](ss-jpa-authentication.png)

1. Dependencies

- For Spring Data JPA and Hibernate, Spring Security APIs and MySQL JDBC Driver:

``` xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <scope>runtime</scope>
</dependency>
```

2. Configure Data Source properties

- Need to specify the database connection information in the application.properties files as follows:

``` properties
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=
spring.datasource.platform=h2

spring.jpa.database-platform=org.hibernate.dialect.H2Dialect
spring.jpa.defer-datasource-initialization=true
spring.jpa.hibernate.ddl-auto=create-drop
```

3. User class

- To use Spring Data JPA, we need to code a model class that maps with the users table in the database.

``` java
@Entity
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
 
    private String username;
    private String password;
    private String role;
    private boolean enabled;
 
    // getters and setters are not shown for brevity

}
```

4. UserRepository class

- Extend JpaRepository and add findByUsername() method

``` java
public interface UserRepository extends JpaRepository<User, Long> {
 
    Optional<User> findByUsername(String username);
}
```

5. Implement UserDetails

- This class wraps an instance of User class, which is injected via constructor. And we override methods defined by the UserDetails interface, to be used by Spring Security in the authentication process.

``` java
public class MyUserDetails implements UserDetails {
 
    private User user;
     
    public MyUserDetails(User user) {
        this.user = user;
    }
 
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(user
                .getRoles()
                .split(","))
                .map(SimpleGrantedAuthority::new)
                .toList();;
    }
 
    @Override
    public String getPassword() {
        return user.getPassword();
    }
 
    @Override
    public String getUsername() {
        return user.getUsername();
    }
 
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
 
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
 
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
 
    @Override
    public boolean isEnabled() {
        return true;
    }
 
}
```

6. Implement UserDetailsService

- This class makes use of an implementation of UserRepository, which will be created and injected by Spring Data JPA. Here, we override the loadUserByUsername() method to authentication the users.

``` java
@Service
public class MyUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public MyUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository
                .findByUsername(username)
                .map(SecurityUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("Username not found: " + username));
    }
}
```

7. Configure authentication provider + HTTP Security

- Finally, we connect all the pieces together by coding a Spring Security configuration class WebSecurityConfig with the following code.

``` java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
  
    @Bean // or can autowire MyUserDetailsService
    public UserDetailsService userDetailsService() {
        return new MyUserDetailsService();
    } 
    
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
     
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
         
        return authProvider;
    }
 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin().permitAll()
            .and()
            .logout().permitAll();
    }
}
```

NOTE: To use Spring security with Spring Data JPA and Hibernate, we need to supply a DaoAuthenticationProvider which requires UserDetailsService and PasswordEncoder.

### 4.3 LDAP Server
TBC

## 5. JWT
![JWT Flow](jwt-flow-2.png)
![JWT Structure](jwt-structure.png)
- NOTE: spring-security-jwt has been deprecated and refers developers to Spring Security OAuth2 (part of Spring Security 5.2.x). No official documentation examples of using JWT **without** at least having an issuer service to distribute the signing key.

### 5.1 What is it?
JSON Web Token (JWT) is widely used for securing REST APIs, in terms of securely transmitting tokens along with HTTP requests, which facilitates stateless and secure communication between REST clients and API backend.
 
- JWT is a JSON based security token for API Authentication.
- JWT can contain unlimited amount of data (unlike cookies).
- JWT can be seen, but not modifiable once sent.
- JWT is just serialized, NOT encrypted.
- JWTs can be signed using a secret (with HMAC algorithm) or a public/private key pair using RSA.
- JWT structure and flow shown in above images.

### 5.2 Method 1 - Filter-based JWT (No OAuth)
- This is a custom implementation and requires a custom security filter with JWT utility class.
- Useful for small applications.

## 6. OAuth
![OAuth2.0 Flow](OAuth-flow.jpg)

### 6.1 What is it?
- OAuth is an Open standard for **authorization** (NOT an API or a service).
- Can use JWT as a token for OAuth.
- OAuth uses both server-side & client-side storage.
- It has a server that keeps track of tokens.
- The purpose of OAuth is to allow users to access data using client software, such as browse based apps, native mobile apps or desktop apps.
- The client software can be authorized to access the resources on behalf of end user using access token.


### 6.2 Method 2 - OAuth2 JWT
- This has built-in functionality and requires a custom JWT authentication server.
- JWT is a mechanism for transferring data, NOT for securing it.
- A JWT is only secure when it's used in tandem with encryption & transport security methodologies.
- If one is creating a bearer token... why not make use of the built-in functionality of OAuth schema designed with built-in security functionality to specifically work with JWT's?
- Therefore, using external solutions (method 1) seems nonsensical.
- Useful for increasing security of JWT.

This is handy in circumstances where an application has delegated its authority management to an authorization server (for example, Okta or Spring Authorization Server). This authorization server can be consulted by resource servers to authorize requests.

In this tutorial, you will use self-signed JWTs which will eliminate the need to introduce an authorization server. While this works for this example, your application requirements might be different so when is it no longer acceptable to use self-signed JWTs?

When you reach the point where the trade-offs for self-signed JWTs are not acceptable. An example might be the moment you want to introduce refresh tokens.
I'd add that a distinct authorization server makes more sense when you have more than one service or you want to be able to harden security (isolating something as critical as authentication provides value because the attack surface is reduced).





