package br.com.forum_hub.domain.usuario;

import br.com.forum_hub.domain.perfil.PerfilNome;
import br.com.forum_hub.domain.perfil.PerfilRepository;
import br.com.forum_hub.infra.email.EmailService;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class RegistroService {

    private final UsuarioRepository usuarioRepository;
    private final PerfilRepository perfilRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public RegistroService(UsuarioRepository usuarioRepository, PerfilRepository perfilRepository, PasswordEncoder passwordEncoder, EmailService emailService) {
        this.usuarioRepository = usuarioRepository;
        this.perfilRepository = perfilRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    @Transactional
    public Usuario cadastrar(DadosCadastroUsuario dados, boolean verificado) {
        var senhaCriptografada = passwordEncoder.encode(dados.senha());

        var perfil = perfilRepository.findByNome(PerfilNome.ESTUDANTE);
        var usuario = new Usuario(dados, senhaCriptografada, perfil, verificado);

        if (!verificado) {
            emailService.enviarEmailVerificacao(usuario);
        }

        return usuarioRepository.save(usuario);
    }

    @Transactional
    public void verificarEmail(String codigo) {
        var usuario = usuarioRepository.findByToken(codigo).orElseThrow();
        usuario.verificar();
    }
}
