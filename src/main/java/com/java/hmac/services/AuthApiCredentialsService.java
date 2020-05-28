package com.java.hmac.services;

import com.java.hmac.dto.AuthApiCredentials;

public interface AuthApiCredentialsService {
    AuthApiCredentials save(AuthApiCredentials authApiCredentials);
    AuthApiCredentials find(String clientId);
}
