This project is a simple, minimal implementation of an OAuth2
Authorization Server for use with Spring Cloud sample apps. It has a
context root of `/uaa` (so that it won't share cookies with other apps
running on other ports on the root resource). OAuth2 endpoints are:

* `/uaa/oauth/token` the Token endpoint, for clients to acquire access
  tokens. There is one client ("acme" with secret "acmesecret"). With
  Spring Cloud Security this is the `oauth2.client.tokenUri`.
* `/uaa/oauth/authorize` the Authorization endpoint to obtain user
  approval for a token grant.  Spring Cloud Security configures this
  in a client app as `oauth2.client.authorizationUri`.
* `/uaa/oauth/check_token` the Check Token endpoint (not part of the
  OAuth2 spec). Can be used to decode a token remotely. Spring Cloud
  Security configures this in a client app as
  `oauth2.resource.tokenInfoUri`.

##授权服务器相关资料

这只是一个授权服务器,为资源服务器提供安全服务

###授权schema.sql

schema.sql:https://github.com/spring-projects/spring-security-oauth/blob/master/spring-security-oauth2/src/test/resources/schema.sql

###UserDetailsService (登录用户)

http://docs.spring.io/spring-security/site/docs/current/reference/html/appendix-schema.html

http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/

##即是授权服务器又是资源服务器

https://github.com/spring-projects/spring-boot/tree/master/spring-boot-samples/spring-boot-sample-secure-oauth2


##资源服务器

https://github.com/spring-projects/spring-boot/tree/master/spring-boot-samples/spring-boot-sample-secure-oauth2-resource


##其他

https://spring.io/blog/2015/02/03/sso-with-oauth2-angular-js-and-spring-security-part-v