package com.kcb.payment_initiator.controller;

import com.kcb.payment_initiator.dtos.MpesaRequest;
import com.kcb.payment_initiator.dtos.SingleDataResponse;
import com.kcb.payment_initiator.service.MpesaB2CService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.security.SecureRandom;

@Controller
@RequiredArgsConstructor
@RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
public class MpesaB2CController {
    private final MpesaB2CService mpesaB2CService;

    /**
     * Initiates a B2C payment to the given MSISDN.
     *
     * @param request the payment request. Must contain the MSISDN and the amount.
     * @return an empty HTTP 200 response if the call is successful.
     */
    @PostMapping(value = "/payments/b2c")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Void> initiateB2C(@RequestBody @Valid MpesaRequest request) {
        try {
            ThreadContext.put("ENDPOINT", "/payments/b2c");
            ThreadContext.put("msisdn", request.getMsisdn());
            ThreadContext.put("METHOD", "POST");
            ThreadContext.put("REQUEST_ID", String.valueOf((new SecureRandom().nextInt(9000000) + 1000000)));
            return mpesaB2CService.sendB2CPayment(request);
        } finally {
            ThreadContext.clearAll();
        }
    }


    /**
     * Exchanges the given authorization code for an access token and retrieves the user's profile
     * information from Google. It then constructs a login request and attempts to log in the user.
     *
     * @param code     the authorization code provided by Google OAuth
     * @param scope    the scope of access requested
     * @param authUser the authenticated user identifier
     * @param prompt   the prompt parameter from the OAuth flow
     * @return a SingleDataResponse containing the login response
     */
    @GetMapping(value = "/googleCallBackAuth", produces = "application/json")
    @ResponseStatus(value = HttpStatus.OK)
    public SingleDataResponse<Object> grantCode(@RequestParam("code") String code, @RequestParam("scope") String scope,
                                                @RequestParam("authuser") String authUser, @RequestParam("prompt") String prompt) {
        String mappedEndpoint = "auth/googleCallBackAuth";
        try {
            ThreadContext.put("ENDPOINT", mappedEndpoint);
            ThreadContext.put("METHOD", "GET");
            return mpesaB2CService.grantCode(code, scope, authUser, prompt);
        } finally {
            ThreadContext.clearAll();
        }
    }


}
