package com.kcb.payment_initiator.configurations;



import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.client.ClientHttpRequestFactories;
import org.springframework.boot.web.client.ClientHttpRequestFactorySettings;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.time.Duration;

@Configuration
@RequiredArgsConstructor
public class RestClientConfig {

    private final ApplicationConfigs coreConfigs;

    /**
     * Create a {@link RestClient} instance with the default settings but with overridden
     * connect and read timeouts.
     *
     * @return a {@link RestClient} instance
     */
    @Bean
    public RestClient restClient() {
        return RestClient.builder()
                .requestFactory(getClientHttpRequestFactory())
                .build();
    }

    /**
     * Return a {@link ClientHttpRequestFactory} instance with the default settings but with overridden
     * connect and read timeouts.
     *
     * @return a {@link ClientHttpRequestFactory} instance
     */
    private ClientHttpRequestFactory getClientHttpRequestFactory() {

        ClientHttpRequestFactorySettings settings = ClientHttpRequestFactorySettings.DEFAULTS
                .withConnectTimeout(Duration.ofSeconds(coreConfigs.getRestCallConnectTimeout()))
                .withReadTimeout(Duration.ofSeconds(coreConfigs.getRestCallReadTimeout()));
        return ClientHttpRequestFactories.get(settings);
    }
}