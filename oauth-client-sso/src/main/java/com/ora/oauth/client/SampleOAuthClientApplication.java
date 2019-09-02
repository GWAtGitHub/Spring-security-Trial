package com.ora.oauth.client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

//There are 2 features behind @EnableOAuth2Sso: the OAuth2 client, and the authentication
//@EnableOAuth2Sso
@EnableOAuth2Client
@RestController
@SpringBootApplication
public class SampleOAuthClientApplication extends WebSecurityConfigurerAdapter {

    /* First off we can inject an OAuth2ClientContext and
       use it to build an authentication filter that we add to our security configuration*/
    @Autowired
    OAuth2ClientContext oAuth2ClientContext;

    public static void main(String[] args) {
      /*  Properties props = System.getProperties();
        props.put("http.proxyHost", "www-proxy.us.oracle.com");
        props.put("http.proxyPort", "80");*/
        SpringApplication.run(SampleOAuthClientApplication.class, args);
    }

    @GetMapping("/user")
    // It’s not a great idea to return a whole Principal in a /user endpoint like that
    // (it might contain information you would rather not reveal to a browser client).
    public Principal user(Principal principal) {
        return principal;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
  /*
 antMatcher() is a method of HttpSecurity, it has nothing to do with authorizeRequests().
 Basically, http.antMatcher() tells Spring to only configure HttpSecurity if the path matches
 this pattern.

The authorizeRequests().antMatchers() is then used to apply authorization to one or more paths you specify in antMatchers(). Such as permitAll() or hasRole('USER3').
These only get applied if the first http.antMatcher() is matched.*/
        http.
                antMatcher("/**")
                //explicitly authorizeRequests() to the home page and the static resources it contains
                // (we also include access to the login endpoints which handle the authentication)
                .authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll()
                //All other requests (e.g. to the /user endpoint) require authentication.
                .anyRequest().authenticated()
                //Spring Security has built in support for a /logout endpoint which will do the right thing for us
                // (clear the session and invalidate the cookie).
                .and().logout().logoutSuccessUrl("/").permitAll()
                /*The /logout endpoint requires us to POST to it, and to protect the user from Cross Site Request Forgery (CSRF, pronounced
                 "sea surf"), it requires a token to be included in the request.
                  The value of the token is linked to the current session, which is what provides the protection, so we need a way
                  to get that data into our JavaScript app.*/
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                /*Many JavaScript frameworks have built in support for CSRF (e.g. in Angular they call it XSRF),
                but it is often implemented in a slightly different way than the out-of-the box behaviour of Spring Security.
                 For instance in Angular the front end would like the server to send it a cookie called "XSRF-TOKEN"
                 and if it sees that, it will send the value back as a header named "X-XSRF-TOKEN".

                 We can implement the same behaviour with our simple jQuery client, and then the server side changes
                 will work with other front end implementations with no or very few changes. To teach Spring Security about this we need to add a filter that creates the cookie and
                also we need to tell the existing CRSF filter about the header name. In the WebSecurityConfigurer:*/

                .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
    }
//Handle REDIRECTS
    /* explicitly support the redirects from our app to Facebook.
    This is handled in Spring OAuth2 with a servlet Filter, and the filter is already available in the application
     context because we used @EnableOAuth2Client. All that is needed is
    to wire the filter up so that it gets called in the right order in our Spring Boot application. To do that we need a FilterRegistrationBean:

    We autowire the already available filter, and register it with a sufficiently low order that it comes before the main Spring Security filter.
    In this way we can use it to handle redirects signaled by expceptions in authentication requests */


    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    public RestTemplate restTemplate() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();

        Proxy proxy= new Proxy(Proxy.Type.HTTP, new InetSocketAddress("www-proxy.us.oracle.com", 80));

        requestFactory.setProxy(proxy);

        return new RestTemplate(requestFactory);
    }
   /* static class ProxyCustomizer implements RestTemplateCustomizer {

        @Override
        public void customize(RestTemplate restTemplate) {
            HttpHost proxy = new HttpHost("proxy.example.com");
            HttpClient httpClient = HttpClientBuilder.create()
                    .setRoutePlanner(new DefaultProxyRoutePlanner(proxy) {

                        @Override
                        public HttpHost determineProxy(HttpHost target,
                                                       HttpRequest request, HttpContext context)
                                throws HttpException {
                            if (target.getHostName().equals("192.168.0.5")) {
                                return null;
                            }
                            return super.determineProxy(target, request, context);
                        }

                    }).build();
            restTemplate.setRequestFactory(
                    new HttpComponentsClientHttpRequestFactory(httpClient));
        }

    }*/

    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(facebook(), "/login/facebook"));
        filters.add(ssoFilter(github(), "/login/github"));
        filter.setFilters(filters);
        return filter;
    }

    private Filter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oAuth2ClientContext);
        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());
        tokenServices.setRestTemplate(template);
        filter.setTokenServices(tokenServices);
        return filter;
    }

    // Access Token Request http://localhost:8080/login/github?code=ef58f050e90fe7002742&state=Ko6K5F
    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }

    class ClientResources {

        @NestedConfigurationProperty
        private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

        @NestedConfigurationProperty
        private ResourceServerProperties resource = new ResourceServerProperties();

        public AuthorizationCodeResourceDetails getClient() {
            return client;
        }

        public ResourceServerProperties getResource() {
            return resource;
        }
    }
}
