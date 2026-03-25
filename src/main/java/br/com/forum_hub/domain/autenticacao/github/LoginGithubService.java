package br.com.forum_hub.domain.autenticacao.github;

import br.com.forum_hub.domain.usuario.DadosCadastroUsuario;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;
import java.util.UUID;

@Service
public class LoginGithubService {
    @Value("${github.oauth.client.id}")
    private String clientId;
    @Value("${github.oauth.client.secret}")
    private String clientSecret;
    private final String redirectUri = "http://localhost:8080/login/github/autorizado";

    private final RestClient restClient;
    public LoginGithubService(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
    }

    public String gerarUrl(){
        return UriComponentsBuilder
                .fromUriString("https://github.com/login/oauth/authorize")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", "read:user,user:email,public_repo")
                // adicionar state para proteção CSRF quando aplicável
                .build()
                .toUriString();
    }

    private String obterToken(String code) {
        return restClient.post()
                .uri("https://github.com/login/oauth/access_token")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(Map.of("code", code
                        , "client_id", clientId
                        , "client_secret", clientSecret
                        , "redirect_uri", redirectUri))
                .retrieve()
                .body(Map.class)
                .get("access_token").toString();
    }

    public String enviarRequisicaoEmail(HttpHeaders headers){
        var resposta = restClient.get()
                .uri("https://api.github.com/user/emails")
                .headers(httpHeaders -> httpHeaders.addAll(headers))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(DadosEmail[].class);

        for(DadosEmail dadosEmail : resposta){
            if(dadosEmail.primary() && dadosEmail.verified()){
                return dadosEmail.email();
            }
        }

        return null;
    }

    private DadosCadastroUsuario obterDadosUsuario(HttpHeaders headers, String email) {
        var resposta = restClient.get()
                .uri("https://api.github.com/user")
                .headers(httpHeaders -> httpHeaders.addAll(headers))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(Map.class);

        var nomeCompleto = resposta.get("name").toString();
        var nomeUsuario = resposta.get("login").toString();
        var senha = UUID.randomUUID().toString();

        return new DadosCadastroUsuario(email, senha, nomeCompleto, nomeUsuario, null, null);
    }

    public DadosCadastroUsuario obterDadosOAuth(String code) {
        var token = obterToken(code);
        var headers = new HttpHeaders();
        headers.setBearerAuth(token);
        var email = enviarRequisicaoEmail(headers);
        return obterDadosUsuario(headers, email);
    }
}
