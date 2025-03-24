package com.kcb.payment_initiator.service;


import com.kcb.payment_initiator.dtos.MpesaRequest;
import org.springframework.http.ResponseEntity;

public interface MpesaB2CServiceInterface {
    ResponseEntity<Void> sendB2CPayment(MpesaRequest request);
}