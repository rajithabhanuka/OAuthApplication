package com.java.hmac.security;

import com.java.hmac.constants.Constants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.SortedMap;

@Component
public class AuthMessageSigner {

    private static final Log LOGGER = LogFactory.getLog(AuthMessageSigner.class);

    public String sign(String secret, String algorithm, String method, String url, SortedMap<String, String> parameters) throws Exception {

        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.concat(Constants.AMPERSAND).getBytes(), algorithm);
        Mac mac = Mac.getInstance(secretKeySpec.getAlgorithm());
        mac.init(secretKeySpec);
        StringBuilder signatureBase = new StringBuilder(OAuthUtil.percentEncode(method));
        signatureBase.append(Constants.AMPERSAND);
        signatureBase.append(OAuthUtil.percentEncode(url));
        signatureBase.append(Constants.AMPERSAND);
        int count = 0;
        Iterator bytes = parameters.keySet().iterator();

        while (bytes.hasNext()) {
            String encodedMacBytes = (String) bytes.next();
            ++count;
            signatureBase.append(OAuthUtil.percentEncode(OAuthUtil.percentEncode(encodedMacBytes)));
            signatureBase.append(URLEncoder.encode(Constants.EQUAL, Constants.UTF_8));
            signatureBase.append(OAuthUtil.percentEncode(OAuthUtil.percentEncode((String) parameters.get(encodedMacBytes))));
            if (count < parameters.size()) {
                signatureBase.append(URLEncoder.encode(Constants.AMPERSAND, Constants.UTF_8));
            }
        }

        LOGGER.debug("SignatureBase String: [" + signatureBase.toString() + "]");

        byte[] var12 = mac.doFinal(signatureBase.toString().getBytes());
        byte[] var13 = Base64.encodeBase64(var12);
        return new String(var13);
    }
}
