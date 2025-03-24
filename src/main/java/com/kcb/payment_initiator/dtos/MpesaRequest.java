package com.kcb.payment_initiator.dtos;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@RequiredArgsConstructor
@Setter
@AllArgsConstructor
public class MpesaRequest {

    @NotBlank(message = "Msisdn is required")
    private String msisdn;
    @Min(value = 10, message = "Amount must be greater than 10")
    private double Amount;

}