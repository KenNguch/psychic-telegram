package com.kcb.payment_initiator.configurations;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Getter
public class ApplicationConfigs {

    @Value("${mpesa.consumer.key}")
    private String consumerKey;

    @Value("${mpesa.consumer.secret}")
    private String consumerSecret;

    @Value("${mpesa.oauth.url}")
    private String oauthUrl;

    @Value("${mpesa.b2c.url}")
    private String b2cUrl;

    @Value("${mpesa.shortcode}")
    private String shortCode;

    @Value("${mpesa.initiator.username}")
    private String initiatorName;

    @Value("${mpesa.callback.url}")
    private String callbackUrl;


    @Value("${mpesa.initiator.password}")
    private String password;


    @Value("${mpesa.apiCallConnectTimeout:5000}")
    private int restCallConnectTimeout;

    @Value("${mpesa.apiCallReadTimeout:5000}")
    private int restCallReadTimeout;

    @Value("${payment.app.token.jwtSecret}")
    private String jwtSecret;
    @Value("${payment.app.token.jwtExpirationMs}")
    private long jwtExpirationMs;
    @Value("${payment.app.token.jwtRefreshExpirationMs}")
    private long refreshTokenDurationMs;

    @Value("${payment.app.google.clientId}")
    private String googleClientID;

    @Value("${payment.app.google.clientSecret}")
    private String googleClientSecret;

    @Value("${payment.app.google.userInfoUrl:https://www.googleapis.com/oauth2/v2/userinfo}")
    private String googleUserInfoUrl;

    @Value("${payment.app.google.redirectUrl}")
    private String googleRedirectUrl;

    @Value("${payment.app.google.authorizationTokenUrl}")
    private String googleAuthorizationTokenUrl;

}
