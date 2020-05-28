package com.java.hmac.security;

import com.java.hmac.constants.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class OAuthSecurityFilter extends OncePerRequestFilter {

    private static Log LOGGER = LogFactory.getLog(OAuthSecurityFilter.class);

    private static final String HTTPS_PROTOCOL = "https";
    private static final String HTTP_PROTOCOL = "http";
    private static final String ERROR_SIGNATURE_MISMATCH_LOG_FORMAT = "OAuth calculation failed! requestParams: [%s], method: [%s], url: [%s], OAuthHeader: [%s], signature_https: [%s],signature_http: [%s]";

    @Autowired
    private OAuthUtil oAuthUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        TreeMap<String, String> requestParamMap = new TreeMap<String, String>();

        /*Get the Authorization header*/
        String requestAuthHeader = request.getHeader(Constants.OAUTH_HEADER_KEY);

        try {

            Map<String, String> authHeaderParams = null;

            if (requestAuthHeader != null && requestAuthHeader.contains(Constants.OAUTH_KEYWORD)) {
                /*Checking whether OAuth request or Not */

                authHeaderParams = oAuthUtil.decodeAuthorization(requestAuthHeader);
                authHeaderParams.remove(Constants.OAUTH_REALM);
                requestParamMap.putAll(authHeaderParams);
            }

            /*Get the request parameters in the request to create the signature*/

            Map<String, String[]> authRequestParams = request.getParameterMap();

            Iterator headerParamIterator = authRequestParams.keySet().iterator();

            String[] signature;
            int recalculatedSignature;
            while (headerParamIterator.hasNext()) {
                String headerParam = (String) headerParamIterator.next();
                signature = (String[]) authRequestParams.get(headerParam);
                StringBuffer calculatedSignature = new StringBuffer();
                recalculatedSignature = 0;
                String[] requiredOAuthParameter = signature;
                int len$ = signature.length;

                for (int i$ = 0; i$ < len$; ++i$) {
                    String value = requiredOAuthParameter[i$];
                    ++recalculatedSignature;
                    calculatedSignature.append(value);
                    if (recalculatedSignature < signature.length) {
                        calculatedSignature.append(Constants.COMMA);
                    }
                }

                requestParamMap.put(headerParam, calculatedSignature.toString());
            }

            StringBuffer missingAuthParams = new StringBuffer();
            boolean availableMissingAuthParam = false;
            signature = OAuthUtil.REQUIRED_OAUTH_PARAMETERS;
            int signatureLength = signature.length;

            /*Validating the Auth Parameters with the Request*/

            for (recalculatedSignature = 0; recalculatedSignature < signatureLength; ++recalculatedSignature) {
                String signatureParam = signature[recalculatedSignature];
                if (!requestParamMap.containsKey(signatureParam)) {
                    LOGGER.error("Missing OAuth parameter: [" + signatureParam + "]");
                    missingAuthParams.append(Constants.SPACE + signatureParam);
                    availableMissingAuthParam = true;
                }
            }

            if (availableMissingAuthParam) {
                ((HttpServletResponse) response).sendError(400, String.format(Constants.ERROR_MESSAGE_FORMAT_MISSING_PARAMS, missingAuthParams));
            } else {

                /*For HTTPS requests*/

                String authSignature = (String) requestParamMap.remove(Constants.OAUTH_SIGNATURE);
                String signatureHttps = (new AuthMessageSigner()).sign(
                        oAuthUtil.retrieveSharedSecret((String) requestParamMap.get(Constants.OAUTH_CONSUMER_KEY)),
                        oAuthUtil.mapToJava((String) requestParamMap.get(Constants.OAUTH_SIGNATURE_METHOD)),
                        request.getMethod(),
                        getHttpsRequestURL(request),
                        requestParamMap
                );
                if (authSignature.equals(signatureHttps)) {
                    filterChain.doFilter(request, response);
                } else {

                    /*For HTTP requests*/

                    String signatureHttp = (new AuthMessageSigner()).sign(
                            oAuthUtil.retrieveSharedSecret((String) requestParamMap.get(Constants.OAUTH_CONSUMER_KEY)),
                            oAuthUtil.mapToJava((String) requestParamMap.get(Constants.OAUTH_SIGNATURE_METHOD)),
                            request.getMethod(),
                            getHttpRequestURL(request),
                            requestParamMap
                    );
                    if (authSignature.equals(signatureHttp)) {
                        filterChain.doFilter(request, response);
                    } else {
                        LOGGER.error(String.format(ERROR_SIGNATURE_MISMATCH_LOG_FORMAT, requestParamMap.toString(), request.getMethod(), request.getRequestURL().toString(), requestAuthHeader, signatureHttps, signatureHttp));
                        response.sendError(401, Constants.ERROR_MESSAGE_SIGNATURE_MISMATCH);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            throw new ServletException(e);
        }

    }

    /**
     * Get HTTPS url from request
     *
     * @param request HttpServletRequest
     * @return https url
     */
    private String getHttpsRequestURL(HttpServletRequest request) {
        String requestUrl = request.getRequestURL().toString();
        requestUrl = requestUrl.replaceFirst(request.getScheme(), HTTPS_PROTOCOL);
        return requestUrl;
    }

    /**
     * Get HTTP url from request
     *
     * @param request HttpServletRequest
     * @return http url
     */
    private String getHttpRequestURL(HttpServletRequest request) {
        String requestUrl = request.getRequestURL().toString();
        requestUrl = requestUrl.replaceFirst(request.getScheme(), HTTP_PROTOCOL);
        return requestUrl;
    }
}
