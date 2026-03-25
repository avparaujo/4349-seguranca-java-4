package br.com.forum_hub.controller;

import br.com.forum_hub.domain.autenticacao.facebook.LoginFacebookService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/login/facebook")
public class LoginFacebookController {
    private final LoginFacebookService loginFacebookService;

    public LoginFacebookController(LoginFacebookService loginFacebookService) {
        this.loginFacebookService = loginFacebookService;
    }

    @GetMapping
    public ResponseEntity<Void> redirecionarFacebook() {
        var url = loginFacebookService.gerarUrl();

        var headers = new HttpHeaders();
        headers.setLocation(URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/autorizado")
    public ResponseEntity<String> obterToken(@RequestParam String code) {
        var token = loginFacebookService.obterToken(code);
        return ResponseEntity.ok(token);
    }
}
