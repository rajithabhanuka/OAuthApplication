package com.java.hmac.constants;

import java.util.regex.Pattern;

/*
Bhanuka 28/05/2020
*/

public interface Constants {

    /*OAuth related String constants*/

    String OAUTH_HEADER_KEY = "Authorization";
    String OAUTH_KEYWORD = "OAuth";
    String OAUTH_REALM = "realm";
    String OAUTH_SIGNATURE = "oauth_signature";
    String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
    String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
    String OAUTH_TIMESTAMP = "oauth_timestamp";
    String OAUTH_NONCE = "oauth_nonce";
    String OAUTH_VERSION = "oauth_version";

    String CRYPTO_KEY_INDEX_ONE = "1";
    String CRYPTO_KEY_INDEX_TWO = "2";

    /*Error messages for OAuth*/

    String ERROR_MESSAGE_FORMAT_MISSING_PARAMS = "Missing:%s";
    String ERROR_MESSAGE_SIGNATURE_MISMATCH = "OAuth signature did not match";
    String ERROR_MESSAGE_FORMAT_UNSUPPORTED_ALGORITHM = "Signature algorithm of %s is unsupported.";

    /* Texts for decoding */

    String UTF_8 = "UTF-8";
    String AMPERSAND = "&";
    String EQUAL = "=";
    String SPACE = " ";
    String COMMA = ",";
    String PLUS = "+";
    String TILDA = "~";
    String ASTERISK = "*";
    String COLON = ":";
    String SEMICOLON = ";";
    String SLASH = "/";
    String DOT = ".";
    String UNDERSCORE = "_";
    String MINUS = "-";
    String URL_ENCODED_SPACE = "%20";
    String URL_ENCODED_ASTERISK = "%2A";
    String URL_ENCODED_TILDA = "%7E";
    String EMPTY_STRING = "";

    String CONSUME_APPLICATION_JSON = "application/json";

    /*OAuthUtil static variables*/

    String[] REQUIRED_OAUTH_PARAMETERS = new String[]{
            Constants.OAUTH_CONSUMER_KEY,
            Constants.OAUTH_SIGNATURE_METHOD,
            Constants.OAUTH_SIGNATURE,
            Constants.OAUTH_TIMESTAMP,
            Constants.OAUTH_NONCE,
            Constants.OAUTH_VERSION};
    String OAUTH_POST_BODY_PARAMETER = "oauth_body_hash";
    Pattern AUTHORIZATION = Pattern.compile("\\s*(\\w*)\\s+(.*)");
    Pattern KEY_VALUE_PAIR = Pattern.compile("(\\S*)\\s*\\=\\s*\"([^\"]*)\"");
    String AUTHORIZATION_MATCHER_SPLIT_FORMAT = "\\s*,\\s*";

    /*ApiKeyFilter static variables*/

    String MISSING_HEADER = "Authorization header required!";
    String INVALID_API_KEY = "API key is invalid!";

    /*OAuthSecurityFilter static variables*/

    String HTTPS_PROTOCOL = "https";
    String HTTP_PROTOCOL = "http";
    String ERROR_SIGNATURE_MISMATCH_LOG_FORMAT = "OAuth calculation failed! requestParams: [%s], method: [%s], url: [%s], OAuthHeader: [%s], signature_https: [%s],signature_http: [%s]";

}
