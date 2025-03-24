package com.kcb.payment_initiator.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;



@AllArgsConstructor
@RequiredArgsConstructor
@Setter
@Getter
public class GoogleUserInfo {

    private String firstName;

    private String lastName;

    private String email;


}
