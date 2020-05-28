package com.java.hmac.services;

import com.java.hmac.dto.AuthApiCredentials;
import org.springframework.stereotype.Service;

@Service
public class AuthApiCredentialsServiceImpl implements AuthApiCredentialsService{

    @Override
    public AuthApiCredentials save(AuthApiCredentials authApiCredentials) {
        return null;
    }

    @Override
    public AuthApiCredentials find(String clientId) {

        // TO DO
        AuthApiCredentials authApiCredentials = new AuthApiCredentials();
        authApiCredentials.setClientId("test");
        authApiCredentials.setClientSecret("Approve");
        return authApiCredentials;
    }
}
