package com.java.hmac;

import com.java.hmac.constants.Constants;
import com.java.hmac.security.AuthMessageSigner;
import com.java.hmac.security.OAuthUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.yaml.snakeyaml.util.UriEncoder;

import javax.servlet.ServletException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.TreeMap;

@SpringBootTest
class HmacApplicationTests {

    @Autowired
    private OAuthUtil oAuthUtil;

    @Test
    void contextLoads() {
    }

    @Test
    public void generateSignature() throws Exception {

        TreeMap<String, String> requestParamMap = new TreeMap<String, String>();
        requestParamMap.put(Constants.OAUTH_CONSUMER_KEY, "Test");
        requestParamMap.put(Constants.OAUTH_NONCE, "OkQ6HsRM1FD");
        requestParamMap.put(Constants.OAUTH_SIGNATURE_METHOD, "HMAC-SHA1");
        requestParamMap.put(Constants.OAUTH_TIMESTAMP, "1590732909");
        requestParamMap.put(Constants.OAUTH_VERSION, "1.0");

        String baseURL = "http://localhost:8080/o/api/users/{100}";
        String uriEncoder = UriEncoder.encode(baseURL);

        String signatureHttps = (new AuthMessageSigner()).sign(
                "Approve",
                "HmacSHA1",
                "GET",
                uriEncoder,
                requestParamMap
        );

        System.out.println(signatureHttps);
    }

}
