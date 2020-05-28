package com.java.hmac.security;

import com.java.hmac.constants.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ApiKeyFilter extends OncePerRequestFilter {

    private static Log LOGGER = LogFactory.getLog(ApiKeyFilter.class);

    private static final String MISSING_HEADER = "Authorization header required!";
    private static final String INVALID_API_KEY = "API key is invalid!";

    @Value( "${api.key}" )
    private String apiKey;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestAuthHeader = httpServletRequest.getHeader(Constants.OAUTH_HEADER_KEY);

        if (requestAuthHeader != null) {
            /* api key is getting from a application.properties */
            if (requestAuthHeader.equals(apiKey)) {
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            } else {
                httpServletResponse.sendError(401, INVALID_API_KEY);
            }


        } else {
            LOGGER.error("Missing OAuthorization header");
            httpServletResponse.sendError(400, MISSING_HEADER);
        }

    }
}
