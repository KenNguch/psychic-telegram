package com.kcb.payment_initiator.dtos;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@RequiredArgsConstructor
@Setter
@AllArgsConstructor
public class MpesaB2CRequest {
    private String InitiatorName;
    private String SecurityCredential;
    private String CommandID;
    private double Amount;
    private String PartyA;
    private String PartyB;
    private String Remarks;
    private String QueueTimeOutURL;
    private String ResultURL;
}