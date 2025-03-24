package com.kcb.payment_initiator.dtos;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;


@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SingleDataResponse<T> {

    private boolean success;
    private String message ;
    private T data = (T) List.of();
    private String code ;
}
