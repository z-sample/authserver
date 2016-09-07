package demo;

import java.security.KeyPair;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;


@Configuration
@ComponentScan
@EnableAutoConfiguration
@Controller
@SessionAttributes("authorizationRequest")//授权页面(authorize.ftl)中用到了
public class AuthserverApplication extends WebMvcConfigurerAdapter {


    public static void main(String[] args) {
        SpringApplication.run(AuthserverApplication.class, args);
    }

    //webmvc 配置
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("login");//security.oauth2.sso.login-path
        registry.addViewController("/oauth/confirm_access").setViewName("authorize");
    }

    //security 配置
    @Configuration
    @Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
    protected static class LoginConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.formLogin().loginPage("/login").permitAll().and().authorizeRequests()
                    .anyRequest().authenticated();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.parentAuthenticationManager(authenticationManager);
        }
    }

    //主要的配置
    @Configuration
    @EnableAuthorizationServer
    protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Bean
        public JwtAccessTokenConverter jwtAccessTokenConverter() {
            //JSON Web Token (JWT) 是一个自我认证的记号，能够包含用户标识、角色和用户权限等信息，能够被任何人方便解析和使用安全的key实现验证
            //JsonWebTokenUtility
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            KeyPair keyPair = new KeyStoreKeyFactory(
                    new ClassPathResource("keystore.jks"), "foobar".toCharArray())
                    .getKeyPair("test");
            converter.setKeyPair(keyPair);
            return converter;
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            //注册客户端(第三方应用)
            clients.inMemory()
                    .withClient("acme")//client_id
                    .secret("acmesecret")//client_secret
                    .authorizedGrantTypes("authorization_code", "refresh_token", "password").scopes("openid")

                    .and()
                    .withClient("zero")//client_id
                    .secret("zerosecret")//client_secret
                    .authorizedGrantTypes("authorization_code", "refresh_token", "password").scopes("openid");

        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints)
                throws Exception {
            endpoints.authenticationManager(authenticationManager).accessTokenConverter(
                    jwtAccessTokenConverter());
//            endpoints.userApprovalHandler()//TokenStoreUserApprovalHandlerTokenStore
            //TokenStore实现类:JwtTokenStore,RedisTokenStore,JdbcTokenStore,InMemoryTokenStore
//            endpoints.tokenStore()//JwtTokenStore,
            //UserDetailsService实现类:InMemoryUserDetailsManager,JdbcUserDetailsManager
//            endpoints.userDetailsService()//InMemoryUserDetailsManager ,debug createUser(UserDetails user)方法可以发现Spring创建了用户:{username:"user",password:"password"...}
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer)
                throws Exception {
            oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess(
                    "isAuthenticated()");
            //curl -H "Authorization: bearer [access_token]" localhost:8080/flights/1
            //默认是将client_id等附加在header中的,这里允许将client_id等在form中提交过来
            oauthServer.allowFormAuthenticationForClients();
        }

    }
}
