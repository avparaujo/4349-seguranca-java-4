package br.com.forum_hub.controller;

import br.com.forum_hub.domain.autenticacao.A2fService;
import br.com.forum_hub.domain.usuario.Usuario;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class A2fController {

    private final A2fService a2fService;

    public A2fController(A2fService a2fService) {
        this.a2fService = a2fService;
    }

    @PatchMapping("/configurar-a2f")
    public ResponseEntity<String> gerarQrCode(@AuthenticationPrincipal Usuario logado){
        var url = a2fService.gerarQrCode(logado);
        return ResponseEntity.ok(url);
    }

    @PatchMapping("/ativar-a2f")
    public ResponseEntity<Void> ativarA2f(@RequestParam String codigo, @AuthenticationPrincipal Usuario logado){
        a2fService.ativarA2f(codigo, logado);
        return ResponseEntity.noContent().build();
    }
}
