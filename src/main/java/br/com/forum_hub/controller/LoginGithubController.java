package br.com.forum_hub.controller;

import br.com.forum_hub.domain.autenticacao.DadosToken;
import br.com.forum_hub.domain.autenticacao.TokenService;
import br.com.forum_hub.domain.autenticacao.github.LoginGithubService;
import br.com.forum_hub.domain.usuario.RegistroService;
import br.com.forum_hub.domain.usuario.Usuario;
import br.com.forum_hub.domain.usuario.UsuarioService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/login/github")
public class LoginGithubController {
    private final LoginGithubService loginGithubService;
    private final UsuarioService usuarioService;
    private final RegistroService registroService;
    private final TokenService tokenService;

    public LoginGithubController(LoginGithubService loginGithubService, UsuarioService usuarioService, RegistroService registroService, TokenService tokenService) {
        this.loginGithubService = loginGithubService;
        this.usuarioService = usuarioService;
        this.registroService = registroService;
        this.tokenService = tokenService;
    }

    @GetMapping
    public ResponseEntity<Void> redirecionarGithub() {
        var url = loginGithubService.gerarUrl();

        var headers = new HttpHeaders();
        headers.setLocation(URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/autorizado")
    public ResponseEntity<DadosToken> autenticarUsuario(@RequestParam String code) {
        var dadosUsuario = loginGithubService.obterDadosOAuth(code);
        var usuario = usuarioService.obterUsuarioPorEmail(dadosUsuario.email())
                .orElseGet(() -> registroService.cadastrar(dadosUsuario, true));

        var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return ResponseEntity.ok(tokenService.dadosToken(usuario, false));
    }
}
