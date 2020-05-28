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

/*
Bhanuka 28/05/2020
*/

public class OAuthSecurityFilter extends OncePerRequestFilter {

    private static Log LOGGER = LogFactory.getLog(OAuthSecurityFilter.class);

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

            /*Checking for requestOAuthHeader whether it singed with OAuth or Not*/

            if (requestAuthHeader != null && requestAuthHeader.contains(Constants.OAUTH_KEYWORD)) {

                /*Decoding auth header and put it to requestParamMap map */

                authHeaderParams = oAuthUtil.decodeAuthorization(requestAuthHeader);
                authHeaderParams.remove(Constants.OAUTH_REALM);
                requestParamMap.putAll(authHeaderParams);
            }

            /*Get the request parameters in the request and put them to a Map<String, String[]>*/

            Map<String, String[]> authRequestParams = request.getParameterMap();

            Iterator headerParamIterator = authRequestParams.keySet().iterator();

            String[] headerParamValue;
            int countedparametersinheaderParamValue = 0;
            while (headerParamIterator.hasNext()) {
                String headerParamkey = (String) headerParamIterator.next();
                headerParamValue = (String[]) authRequestParams.get(headerParamkey);
                StringBuffer stringBuffer = new StringBuffer();
                //    String[] requiredOAuthParameter = headerParamValue;
                int len$ = headerParamValue.length;

                /*Check for request param contains array values */

                for (int i$ = 0; i$ < len$; ++i$) {
                    String value = headerParamValue[i$];
                    countedparametersinheaderParamValue++;
                    stringBuffer.append(value);
                    if (countedparametersinheaderParamValue < headerParamValue.length) {
                        stringBuffer.append(Constants.COMMA);
                    }
                }

                requestParamMap.put(headerParamkey, stringBuffer.toString());
            }

            StringBuffer missingAuthParams = new StringBuffer();
            boolean MissingAuthParam = false;
            String[] validateSignature = Constants.REQUIRED_OAUTH_PARAMETERS;
            int signatureLength = validateSignature.length;

            /*Validating the Auth Parameters with the Request*/

            for (int i = 0; i < signatureLength; i++) {
                String signatureParam = validateSignature[i];
                if (!requestParamMap.containsKey(signatureParam)) {
                    LOGGER.error("Missing OAuth parameter: [" + signatureParam + "]");
                    missingAuthParams.append(Constants.SPACE + signatureParam);
                    MissingAuthParam = true;
                }
            }

            if (MissingAuthParam) {
                response.sendError(400, String.format(Constants.ERROR_MESSAGE_FORMAT_MISSING_PARAMS, missingAuthParams));
            } else {

                /*Creating a signature For HTTPS requests*/

                String authSignature = (String) requestParamMap.remove(Constants.OAUTH_SIGNATURE);
                String signatureHttps = (new AuthMessageSigner()).sign(
                        oAuthUtil.retrieveSharedSecret((String) requestParamMap.get(Constants.OAUTH_CONSUMER_KEY)),
                        oAuthUtil.mapToJava((String) requestParamMap.get(Constants.OAUTH_SIGNATURE_METHOD)),
                        request.getMethod(),
                        getHttpsRequestURL(request),
                        requestParamMap
                );

                /*Checking the recreated signature and the signature that was sent by request*/

                if (authSignature.equals(signatureHttps)) {
                    filterChain.doFilter(request, response);
                } else {

                    /*Creating a signature For HTTP requests*/

                    String signatureHttp = (new AuthMessageSigner()).sign(
                            oAuthUtil.retrieveSharedSecret((String) requestParamMap.get(Constants.OAUTH_CONSUMER_KEY)),
                            oAuthUtil.mapToJava((String) requestParamMap.get(Constants.OAUTH_SIGNATURE_METHOD)),
                            request.getMethod(),
                            getHttpRequestURL(request),
                            requestParamMap
                    );

                    /*Checking the recreated signature and the signature that was sent by request*/

                    if (authSignature.equals(signatureHttp)) {
                        filterChain.doFilter(request, response);
                    } else {
                        LOGGER.error(String.format(Constants.ERROR_SIGNATURE_MISMATCH_LOG_FORMAT, requestParamMap.toString(), request.getMethod(), request.getRequestURL().toString(), requestAuthHeader, signatureHttps, signatureHttp));
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
        requestUrl = requestUrl.replaceFirst(request.getScheme(), Constants.HTTPS_PROTOCOL);
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
        requestUrl = requestUrl.replaceFirst(request.getScheme(), Constants.HTTP_PROTOCOL);
        return requestUrl;
    }
}
