package com.java.hmac.dto;

public class AuthApiCredentials {

    private String id;
    private String clientId;
    private String clientSecret;

    public String getId() {
        return id;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
}
