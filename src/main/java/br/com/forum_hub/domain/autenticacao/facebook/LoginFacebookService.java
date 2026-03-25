package br.com.forum_hub.domain.autenticacao.facebook;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Map;

@Service
public class LoginFacebookService {
    private final String clientId = "{app-id}";
    private final String clientSecret = "{app-secret}";
    private final String redirectUri = "http://localhost:8080/login/facebook/autorizado";
    private final RestClient restClient;

    public LoginFacebookService(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
    }

    public String gerarUrl() {
        return UriComponentsBuilder
                .fromUriString("https://www.facebook.com/v25.0/dialog/oauth")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", "email,public_profile")
                // adicionar state para proteção CSRF quando aplicável
                .build()
                .toUriString();
    }

    public String obterToken(String code) {
        URI uri = UriComponentsBuilder
                .fromUriString("https://graph.facebook.com/v25.0/oauth/access_token")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("client_secret", clientSecret)
                .queryParam("code", code)
                .build()
                .toUri();
        return restClient.get()
                .uri(uri)
                .retrieve()
                .body(Map.class)
                .get("access_token").toString();
    }
}
