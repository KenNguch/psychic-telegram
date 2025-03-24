package com.kcb.payment_initiator.service;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.kcb.payment_initiator.configurations.ApplicationConfigs;
import com.kcb.payment_initiator.dtos.GoogleUserInfo;
import com.kcb.payment_initiator.dtos.MpesaB2CRequest;
import com.kcb.payment_initiator.dtos.MpesaRequest;
import com.kcb.payment_initiator.dtos.SingleDataResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.kcb.payment_initiator.util.MpesaSecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class MpesaB2CService implements MpesaB2CServiceInterface {

    private ApplicationConfigs applicationConfigs;
    private final RestClient restClient;
    private static final Logger logger = LoggerFactory.getLogger(MpesaB2CService.class);


    private MpesaSecurityUtil mpesaSecurityUtil;

    /**
     * This method sends a Business-to-Consumer (B2C) payment request to the M-Pesa API.
     * <p>
     * The method takes a {@link MpesaRequest} object as an argument and uses it to construct an M-Pesa B2C request payload.
     * The payload is then sent to the M-Pesa B2C API endpoint.
     * <p>
     * The method logs the start and end times of the request and the response from the API.
     * If the request is successful, the method returns a 200 OK response.
     * If the request fails, the method returns a 500 Internal Server Error response.
     *
     * @param request A {@link MpesaRequest} object containing the request details.
     * @return A {@link ResponseEntity} containing the response from the API.
     */
    @Override
    public ResponseEntity<Void> sendB2CPayment(MpesaRequest request) {
        long startTime = System.currentTimeMillis();

        try {
            logger.info("Starting B2C payment request for Msisdn: {}", request.getMsisdn());

            String encryptedPassword = MpesaSecurityUtil.encryptPassword(applicationConfigs.getPassword());
            logger.debug("Encrypted password generated.");

            MpesaB2CRequest requestData = getMpesaB2CRequest(request, encryptedPassword);
            logger.debug("Request payload prepared: {}", requestData);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(mpesaSecurityUtil.getAccessToken());
            logger.debug("Authorization token set.");

            String response = restClient.post()
                    .uri(applicationConfigs.getB2cUrl())
                    .headers(httpHeaders -> httpHeaders.addAll(headers))
                    .body(requestData)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> {
                        logger.error("M-Pesa B2C request failed with HTTP Status: {}", res.getStatusCode());
                        throw new RuntimeException("M-Pesa B2C request failed with HTTP " + res.getStatusCode());
                    })
                    .body(String.class);

            logger.info("M-Pesa B2C API call successful for Msisdn response is : {}", response);

            return ResponseEntity.status(HttpStatus.OK).build();
        } catch (SocketTimeoutException timeoutEx) {
            logger.error("M-Pesa request timed out: {}", timeoutEx.getMessage());
            return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).build();

        } catch (HttpStatusCodeException httpEx) {
            logger.error("M-Pesa returned an HTTP error: {} - {}", httpEx.getStatusCode(), httpEx.getResponseBodyAsString());
            return ResponseEntity.status(httpEx.getStatusCode()).build();

        } catch (CertificateException | IOException | NoSuchPaddingException | NoSuchAlgorithmException |
                 IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            logger.error("Encryption/Communication error occurred: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

        } catch (Exception e) {
            logger.error("Error occurred during M-Pesa B2C payment request: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        } finally {
            logger.info("M-Pesa B2C request completed in {} ms", System.currentTimeMillis() - startTime);
        }

    }

    /**
     * Returns a {@link MpesaB2CRequest} object containing the request details needed for the M-Pesa B2C API call.
     *
     * @param request           A {@link MpesaRequest} object containing the request details.
     * @param encryptedPassword The encrypted password to be used for authentication.
     * @return A {@link MpesaB2CRequest} object containing the request details.
     */
    private MpesaB2CRequest getMpesaB2CRequest(MpesaRequest request, String encryptedPassword) {
        MpesaB2CRequest requestData = new MpesaB2CRequest();
        requestData.setInitiatorName(applicationConfigs.getInitiatorName());
        requestData.setSecurityCredential(encryptedPassword);
        requestData.setCommandID("BusinessPayment");
        requestData.setAmount(request.getAmount());
        requestData.setPartyA(applicationConfigs.getShortCode());
        requestData.setPartyB(request.getMsisdn());
        requestData.setRemarks("B2C Payment");
        requestData.setQueueTimeOutURL(applicationConfigs.getCallbackUrl());
        requestData.setResultURL(applicationConfigs.getCallbackUrl());
        return requestData;
    }


    /**
     * Exchanges the given authorization code for an access token and retrieves the user's profile
     * information from Google. It then generates a new token using the user's email and name.
     *
     * @param code     the authorization code provided by Google OAuth
     * @param scope    the scope of access requested
     * @param authUser the authenticated user identifier
     * @param prompt   the prompt parameter from the OAuth flow
     * @return a SingleDataResponse containing the generated token
     */
    public SingleDataResponse<Object> grantCode(String code, String scope, String authUser, String prompt) {
        long startTime = System.currentTimeMillis();

        try {
            String accessToken = getOauthAccessTokenGoogle(code);
            GoogleUserInfo googleUser = getProfileDetailsGoogle(accessToken);
            //todo -> get the user intenally using the email and generate a new token
            String token = mpesaSecurityUtil.generateTokenFromUser(googleUser.getEmail(), 1L, googleUser.getFirstName() + googleUser.getLastName());
            return SingleDataResponse.builder().data(token).build();
        } catch (Exception e) {
            logger.error(e.getMessage());
        } finally {
            logger.info("Granting Code request completed in {} ms", System.currentTimeMillis() - startTime);
        }
        return SingleDataResponse.builder().data("Error During processing").build();
    }


    /**
     * Uses the given access token to retrieve the user's profile information
     * from the Google OAuth server.
     *
     * @param accessToken the access token to use
     * @return the user's profile information
     */
    private GoogleUserInfo getProfileDetailsGoogle(String accessToken) {
        String response = mpesaSecurityUtil.get(applicationConfigs.getGoogleUserInfoUrl(), accessToken, List.of(HttpStatus.OK), String.class,
                MediaType.APPLICATION_FORM_URLENCODED);
        JsonObject jsonObject = new Gson().fromJson(response, JsonObject.class);
        GoogleUserInfo user = new GoogleUserInfo();
        user.setEmail(jsonObject.get("email").toString().replace("\"", ""));
        user.setFirstName(jsonObject.get("name").toString().replace("\"", ""));
        user.setLastName(jsonObject.get("given_name").toString().replace("\"", ""));
        return user;
    }


    /**
     * Uses the given authorization code to request an access token from the Google OAuth server.
     *
     * @param code the authorization code
     * @return the access token
     */
    private String getOauthAccessTokenGoogle(String code) {
        MultiValueMap<String, Object> params = getGoogleOauthAccessTokenHeader(code);
        String response =
                mpesaSecurityUtil.get(applicationConfigs.getGoogleAuthorizationTokenUrl(), List.of(HttpStatus.OK), params, String.class,
                        MediaType.APPLICATION_FORM_URLENCODED);
        JsonObject jsonObject = new Gson().fromJson(response, JsonObject.class);
        return jsonObject.get("access_token").toString().replace("\"", "");

    }

    /**
     * Generates a MultiValueMap containing the required parameters for the Google OAuth authorization token endpoint.
     *
     * @param code the authorization code
     * @return a MultiValueMap containing the required parameters
     */
    private MultiValueMap<String, Object> getGoogleOauthAccessTokenHeader(String code) {
        MultiValueMap<String, Object> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("redirect_uri", applicationConfigs.getGoogleRedirectUrl());
        params.add("client_id", applicationConfigs.getGoogleClientID());
        params.add("client_secret", applicationConfigs.getGoogleClientSecret());
        params.add("scope", "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile");
        params.add("scope", "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email");
        params.add("scope", "openid");
        params.add("grant_type", "authorization_code");
        return params;
    }


}
