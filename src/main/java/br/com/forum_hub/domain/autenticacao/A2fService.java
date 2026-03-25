package br.com.forum_hub.domain.autenticacao;

import br.com.forum_hub.domain.usuario.Usuario;
import br.com.forum_hub.domain.usuario.UsuarioRepository;
import br.com.forum_hub.infra.exception.RegraDeNegocioException;
import br.com.forum_hub.infra.seguranca.TOTP.TotpService;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

@Service
public class A2fService {
    private final TotpService totpService;
    private final UsuarioRepository usuarioRepository;

    public A2fService(TotpService totpService, UsuarioRepository usuarioRepository) {
        this.totpService = totpService;
        this.usuarioRepository = usuarioRepository;
    }

    @Transactional
    public String gerarQrCode(Usuario logado) {
        var secret = totpService.gerarSecret();
        logado.gerarSecret(secret);
        usuarioRepository.save(logado);
        return totpService.gerarQrCode(logado);
    }

    public void ativarA2f(String codigo, Usuario logado) {
        if (logado.isA2fAtiva()){
            throw new RegraDeNegocioException("Sua autenticação de dois fatores já está ativada!");
        }

        if (!totpService.verificarCodigo(codigo, logado)){
            throw new RegraDeNegocioException("Código inválido!");
        }

        logado.ativarA2f();
        usuarioRepository.save(logado);
    }
}
