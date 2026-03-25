package br.com.forum_hub.controller;

import br.com.forum_hub.domain.autenticacao.*;
import br.com.forum_hub.domain.usuario.Usuario;
import br.com.forum_hub.domain.usuario.UsuarioService;
import br.com.forum_hub.infra.seguranca.TOTP.TotpService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AutenticacaoController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UsuarioService usuarioService;
    private final TotpService totpService;

    public AutenticacaoController(AuthenticationManager authenticationManager, TokenService tokenService, UsuarioService usuarioService, TotpService totpService) {
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
        this.usuarioService = usuarioService;
        this.totpService = totpService;
    }

    @PostMapping("/login")
    public ResponseEntity<DadosToken> efetuarLogin(@Valid @RequestBody DadosLogin dados){
        var authenticationToken = new UsernamePasswordAuthenticationToken(dados.email(), dados.senha());
        var authentication = authenticationManager.authenticate(authenticationToken);
        return ResponseEntity.ok(tokenService.dadosToken((Usuario) authentication.getPrincipal(), true));
    }

    @PostMapping("/verificar-a2f")
    public ResponseEntity<DadosToken> verificarSegundoFator(@Valid @RequestBody DadosA2f dadosA2f){
        var usuario = usuarioService.obterUsuarioPorEmail(dadosA2f.email())
                .orElseThrow();

        if(!totpService.verificarCodigo(dadosA2f.codigo(),  usuario)){
            throw new BadCredentialsException("Código invalido");
        }
        return ResponseEntity.ok(tokenService.dadosToken(usuario, false));
    }

    @PostMapping("/atualizar-token")
    public ResponseEntity<DadosToken> atualizarToken(@Valid @RequestBody DadosRefreshToken dados){
        var refreshToken = dados.refreshToken();
        Long idUsuario = Long.valueOf(tokenService.verificarToken(refreshToken));
        var usuario = usuarioService.getUsuarioById(idUsuario).orElseThrow();
        return ResponseEntity.ok(tokenService.dadosToken(usuario, false));
    }
}
