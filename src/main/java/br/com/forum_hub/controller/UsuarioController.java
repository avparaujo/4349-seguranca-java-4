package br.com.forum_hub.controller;

import br.com.forum_hub.domain.perfil.DadosPerfil;
import br.com.forum_hub.domain.usuario.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
public class UsuarioController {

    private final UsuarioService usuarioService;

    public UsuarioController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
    }

    @GetMapping("/{nomeUsuario}")
    public ResponseEntity<DadosListagemUsuario> exibirPerfil(@PathVariable String nomeUsuario){
        var usuario = usuarioService.buscarPeloNomeUsuario(nomeUsuario);
        return ResponseEntity.ok(new DadosListagemUsuario(usuario));
    }

    @PutMapping("/editar-perfil")
    public ResponseEntity<DadosListagemUsuario> editarPerfil(@RequestBody @Valid DadosEdicaoUsuario dados, @AuthenticationPrincipal Usuario logado){
        var usuario = usuarioService.editarPerfil(logado, dados);
        return ResponseEntity.ok(new DadosListagemUsuario(usuario));
    }

    @PatchMapping("alterar-senha")
    public ResponseEntity<Void> alterarSenha(@RequestBody @Valid DadosAlteracaoSenha dados, @AuthenticationPrincipal Usuario logado){
        usuarioService.alterarSenha(dados, logado);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/desativar")
    public ResponseEntity<Void> desativarUsuario(@PathVariable Long id, @AuthenticationPrincipal Usuario logado){
        usuarioService.desativarUsuario(id, logado);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/reativar-conta/{id}")
    public ResponseEntity<Void> reativarUsuario(@PathVariable Long id){
        usuarioService.reativarUsuario(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/adicionar-perfil/{id}")
    public ResponseEntity<DadosListagemUsuario> adicionarPerfil(@PathVariable Long id, @RequestBody @Valid DadosPerfil dados){
        var usuario = usuarioService.adicionarPerfil(id, dados);
        return ResponseEntity.ok(new DadosListagemUsuario(usuario));
    }
}
