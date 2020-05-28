package com.java.hmac.services;

import com.java.hmac.dto.AuthApiCredentials;

/*
Bhanuka 28/05/2020
*/

public interface AuthApiCredentialsService {
    AuthApiCredentials save(AuthApiCredentials authApiCredentials);
    AuthApiCredentials find(String clientId);
}
