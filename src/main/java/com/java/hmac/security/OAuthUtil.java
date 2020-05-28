package com.java.hmac.security;

import com.java.hmac.constants.Constants;
import com.java.hmac.services.AuthApiCredentialsService;
import com.java.hmac.dto.AuthApiCredentials;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;

/*
Bhanuka 28/05/2020
*/

@Component
public class OAuthUtil {

    @Autowired
    private AuthApiCredentialsService apiCredentialsService;

    private static final Map<String, String> algorithms = new HashMap<String, String>();

    static {
        algorithms.put("HMAC-SHA1", "HmacSHA1");
    }

    public Map<String, String> decodeAuthorization(String authorization) {

        HashMap oauthParameters = new HashMap();

        if(authorization != null) {
            Matcher m = Constants.AUTHORIZATION.matcher(authorization);

            if(m.matches() && Constants.OAUTH_KEYWORD.equalsIgnoreCase(m.group(1))) {

                String[] arr$ = m.group(2).split(Constants.AUTHORIZATION_MATCHER_SPLIT_FORMAT);
                int len$ = arr$.length;

                for(int i$ = 0; i$ < len$; ++i$) {
                    String keyValuePair = arr$[i$];
                    m = Constants.KEY_VALUE_PAIR.matcher(keyValuePair);
                    if(m.matches()) {
                        String key = decodePercent(m.group(Integer.parseInt(Constants.CRYPTO_KEY_INDEX_ONE)));
                        String value = decodePercent(m.group(Integer.parseInt(Constants.CRYPTO_KEY_INDEX_TWO)));
                        oauthParameters.put(key, value);
                    }
                }
            }
        }

        return oauthParameters;
    }

    public String decodePercent(String s) {
        try {
            return URLDecoder.decode(s, Constants.UTF_8);
        } catch (UnsupportedEncodingException var2) {
            throw new RuntimeException(var2.getMessage(), var2);
        }
    }

    public static String percentEncode(String s) {
        if(s == null) {
            return Constants.EMPTY_STRING;
        } else {
            try {
                return URLEncoder.encode(s, Constants.UTF_8).replace(Constants.PLUS, Constants.URL_ENCODED_SPACE).
                        replace(Constants.ASTERISK, Constants.URL_ENCODED_ASTERISK).replace(Constants.URL_ENCODED_TILDA, Constants.TILDA);
            } catch (UnsupportedEncodingException var2) {
                throw new RuntimeException(var2.getMessage(), var2);
            }
        }
    }

    public final String mapToJava(String name) {
        String algorithm = (String)algorithms.get(name);
        if(algorithm == null) {
            throw new UnsupportedOperationException(String.format(Constants.ERROR_MESSAGE_FORMAT_UNSUPPORTED_ALGORITHM, name));
        } else {
            return algorithm;
        }
    }

    public final String retrieveSharedSecret(String key) {
        AuthApiCredentials authApiCredentials = apiCredentialsService.find(key);
        return authApiCredentials == null ? null : authApiCredentials.getClientSecret();
    }

}
