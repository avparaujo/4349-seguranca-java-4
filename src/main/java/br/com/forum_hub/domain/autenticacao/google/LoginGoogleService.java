package br.com.forum_hub.domain.autenticacao.google;

import br.com.forum_hub.domain.autenticacao.github.DadosEmail;
import br.com.forum_hub.domain.usuario.DadosCadastroUsuario;
import com.auth0.jwt.JWT;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.UUID;

@Service
public class LoginGoogleService {
    @Value("${google.oauth.client.id}")
    private String clientId;
    @Value("${google.oauth.client.secret}")
    private String clientSecret;
    private final String redirectUri = "http://localhost:8080/login/google/autorizado";

    private final RestClient restClient;
    public LoginGoogleService(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
    }

    public String gerarUrl(){
        return UriComponentsBuilder
                .fromUriString("https://accounts.google.com/o/oauth2/v2/auth")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", "https://www.googleapis.com/auth/userinfo.email"+
                        "%20https://www.googleapis.com/auth/userinfo.profile")
                .queryParam("response_type", "code")
                // adicionar state para proteção CSRF quando aplicável
                .build()
                .toUriString();
    }

    private String obterToken(String code) {
        return restClient.post()
                .uri("https://oauth2.googleapis.com/token")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(Map.of("code", code
                        , "client_id", clientId
                        , "client_secret", clientSecret
                        , "redirect_uri", redirectUri
                        , "grant_type", "authorization_code"))
                .retrieve()
                .body(Map.class)
                .get("id_token").toString();
    }

    public DadosCadastroUsuario obterDadosOAuth(String code) {
        var token = obterToken(code);
        var decodedJWT = JWT.decode(token);
        var email = decodedJWT.getClaim("email").asString();
        var senha = UUID.randomUUID().toString();
        var nomeCompleto = decodedJWT.getClaim("name").asString();
        var nomeUsuario = email.split("@")[0];
        return new DadosCadastroUsuario(email, senha, nomeCompleto, nomeUsuario, null, null);
    }
}
