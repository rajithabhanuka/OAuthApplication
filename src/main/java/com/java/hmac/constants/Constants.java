package com.java.hmac.constants;

public interface Constants {

    //OAuth related String constants

    String OAUTH_HEADER_KEY = "Authorization";
    String OAUTH_KEYWORD = "OAuth";
    String OAUTH_REALM = "realm";
    String ERROR_MESSAGE_FORMAT_MISSING_PARAMS = "Missing:%s";
    String ERROR_MESSAGE_SIGNATURE_MISMATCH = "OAuth signature did not match";
    String ERROR_MESSAGE_FORMAT_UNSUPPORTED_ALGORITHM = "Signature algorithm of %s is unsupported.";

    //oauth params
    String OAUTH_SIGNATURE = "oauth_signature";
    String OAUTH_CONSUMER_KEY = "oauth_consumer_key";
    String OAUTH_SIGNATURE_METHOD = "oauth_signature_method";
    String OAUTH_TIMESTAMP = "oauth_timestamp";
    String OAUTH_NONCE = "oauth_nonce";
    String OAUTH_VERSION = "oauth_version";

    String CRYPTO_KEY_INDEX_ONE = "1";
    String CRYPTO_KEY_INDEX_TWO = "2";

    //Common texts
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

    String API_KEY = "TEST";
}
