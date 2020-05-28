package com.java.hmac.configs;

import com.java.hmac.security.ApiKeyFilter;
import com.java.hmac.security.OAuthSecurityFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

/*
Bhanuka 28/05/2020
*/

@Configuration
public class WebSecurityConfig {
    private static final String API_KEY_URL_PATTERN = "/a/*";
    private static final String OAUTH_URL_PATTERN = "/o/*";

    private static final String API_KEY_FILTER_NAME = "apiKeyFilter";
    private static final String OAUTH_FILTER_NAME = "oAuthFilter";

    /**
     * Filter registration for for api key filter
     */
    @Bean
    public FilterRegistrationBean apiKeyFilterRegistration() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(apiKeyFilter());
        registrationBean.addUrlPatterns(API_KEY_URL_PATTERN);
        registrationBean.setName(API_KEY_FILTER_NAME);
        registrationBean.setOrder(1);
        return registrationBean;
    }

    /**
     * Bean for api key filter
     */
    @Bean(name = API_KEY_FILTER_NAME)
    public OncePerRequestFilter apiKeyFilter() {
        return new ApiKeyFilter();
    }

    /**
     * Filter registration for OAuth 1.0 filter
     */
    @Bean
    public FilterRegistrationBean oAuthFilterRegistration() {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean();
        registrationBean.setFilter(oAuthFilter());
        registrationBean.addUrlPatterns(OAUTH_URL_PATTERN);
        registrationBean.setName(OAUTH_FILTER_NAME);
        registrationBean.setOrder(1);
        return registrationBean;
    }

    /**
     * Bean for OAuth Filter
     */
    @Bean(name = OAUTH_FILTER_NAME)
    public OncePerRequestFilter oAuthFilter() {
        return new OAuthSecurityFilter();
    }
}
