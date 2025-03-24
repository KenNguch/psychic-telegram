package com.kcb.payment_initiator.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.kcb.payment_initiator.configurations.ApplicationConfigs;
import com.kcb.payment_initiator.service.MpesaB2CService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.springframework.http.HttpHeaders;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class MpesaSecurityUtil {
    private static final Logger logger = LoggerFactory.getLogger(MpesaB2CService.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final ApplicationConfigs applicationConfig;
    private final RestClient restClient;

    public static String encryptPassword(String password) throws CertificateException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate cert = certFactory.generateCertificate(Files.newInputStream(Paths.get("cert_sandbox.pem")));
            PublicKey publicKey = cert.getPublicKey();

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedPassword = cipher.doFinal(password.getBytes());

            return Base64.getEncoder().encodeToString(encryptedPassword);
        }
    }

    public String getAccessToken() {
        // Encode Consumer Key & Secret
        String credentials = "consumerKey" + ":" + "consumerSecret";
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());

        // Set Headers
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + encodedCredentials);

        // Call OAuth API and Extract Token
        return restClient.get()
                .uri(applicationConfig.getOauthUrl())
                .headers(httpHeaders -> httpHeaders.addAll(headers))
                .retrieve()
                .onStatus(HttpStatusCode::isError, (request, response) -> {
                    throw new RuntimeException("Failed to get access token, HTTP " + response.getStatusCode());
                })
                .body(String.class); // Adjust parsing based on response JSON structure
    }


    /**
     * Executes a GET request.
     *
     * @param url           the URL to get
     * @param token         the token to use for authentication
     * @param username      the username to use for authentication
     * @param password      the password to use for authentication
     * @param successStatus the status codes to be considered successful
     * @param urlParams     the parameters to be used in the URL
     * @return the response body as a {@link R}
     * @throws RestClientException if an error occurs
     */
    public <R> R get(String url, String token, String username, String password, List<HttpStatus> successStatus,
                     MultiValueMap<String, Object> urlParams, Class<R> resp, MediaType contentType) throws RestClientException {
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromHttpUrl(url);
        if (urlParams != null && !url.isEmpty()) {
            urlParams.forEach(uriComponentsBuilder::queryParam);
        }
        URI uri = uriComponentsBuilder.build().encode().toUri();

        return restClient.get()
                .uri(uri)
                .headers(headers -> processHeaders(token, username, password, headers, contentType))
                .exchange((request, response) -> {
                    if (!successStatus.isEmpty() && successStatus.contains(
                            HttpStatus.valueOf(response.getStatusCode().value()))) {

                        return convertByteToObject(response.getBody().readAllBytes(), resp);

                    } else {
                        handlerHttpErrors(request, response);
                        return null;
                    }

                });
    }

    /**
     * A convenience method for executing a GET request without any authentication.
     * <p>
     * This method calls {@link #get(String, String, String, String, List, MultiValueMap, Class, MediaType)} with
     * the given parameters and {@code null} for the {@code token}, {@code username}, and {@code password}
     * parameters.
     *
     * @param url           the URL to get
     * @param successStatus the status codes to be considered successful
     * @param urlParams     the parameters to be used in the URL
     * @param resp          the type of the response body
     * @param contentType   the content type of the request
     * @return the response body as a {@link R}
     * @throws RestClientException if an error occurs
     */
    public <R> R get(String url, List<HttpStatus> successStatus,
                     MultiValueMap<String, Object> urlParams, Class<R> resp, MediaType contentType) {
        return get(url, null, null, null, successStatus, urlParams, resp, contentType);
    }

    /**
     * Executes a GET request with the provided URL, token, and expected response type.
     *
     * <p>This method performs a GET request to the specified URL using the provided token for
     * authentication. The response is expected to match one of the success status codes. The
     * response body is deserialized into the specified response type.
     *
     * @param url           the URL to send the GET request to
     * @param token         the token for authentication, used in a Bearer token header
     * @param successStatus the list of HTTP status codes considered successful
     * @param resp          the class type to which the response body should be deserialized
     * @param contentType   the content type of the request
     * @param <R>           the type of the response body
     * @return the response body deserialized into the specified type
     * @throws RestClientException if an error occurs during the request
     */
    public <R> R get(String url, String token, List<HttpStatus> successStatus, Class<R> resp, MediaType contentType) {
        return get(url, token, null, null, successStatus, null, resp, contentType);
    }


    /**
     * Populates the headers of the request with the given authentication credentials.
     *
     * <p>If a token is provided, it is used to set the Bearer authentication header. Otherwise,
     * if a username and password are provided, they are used to set the Basic authentication
     * header. In either case, the "Accept" header is set to "application/json" and the
     * "Content-Type" header is set to "application/json".
     *
     * @param token       the Bearer token to use for authentication
     * @param username    the username to use for authentication
     * @param password    the password to use for authentication
     * @param headers     the headers to populate
     * @param contentType the content type of the request
     */

    private static void processHeaders(String token, String username, String password, HttpHeaders headers,
                                       MediaType contentType) {
        if (StringUtils.isNotBlank(token)) {
            headers.setBearerAuth(token);
        } else if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
            headers.setBasicAuth(username, password);
        }
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        if (!Objects.isNull(contentType)) {
            headers.setContentType(contentType);
        } else {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }
    }


    /**
     * Handles HTTP errors.
     *
     * @param request  the request that resulted in an error
     * @param response the response that caused the error
     */
    private void handlerHttpErrors(HttpRequest request, RestClient.RequestHeadersSpec.ConvertibleClientHttpResponse response) {
//                TODO: Implement error handling
        logger.error("HTTP Error: Request :: {} Response :: {}", response, request);
        throw new RestClientException(response.toString());
    }

    /**
     * This method converts a byte array to an object.
     *
     * @param json       - byte array
     * @param objectType - object type
     * @param <T>        - generic type
     * @return - object
     */
    public static <T> T convertByteToObject(byte[] json, Class<T> objectType) {
        try {

            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            objectMapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper.registerModule(new JavaTimeModule());


            return json == null ? null : objectMapper.readValue(json, objectType);
        } catch (Exception e) {
            logger.error("Failed to convert JSON to object. Error: {}", e.getMessage());
            return null;
        }
    }

    public String generateTokenFromUser(String email, long userId, String username) { // Should receive the user gotten from internal db
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("email", email);

        String token = Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + applicationConfig.getJwtExpirationMs()))
                .signWith(getCustomHmacKey(applicationConfig.getJwtSecret()))
                .compact();

        logger.debug("Generated token::" + token);
        return token;
    }

    public static SecretKey getCustomHmacKey(String customKeyString) {
        byte[] keyBytes = customKeyString.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 64) {
            throw new IllegalArgumentException("The key must be at least 512 bits (64 bytes) long for HS512.");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
