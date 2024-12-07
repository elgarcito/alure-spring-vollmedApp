package med.voll.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import med.voll.api.domain.usuarios.UsuariosRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UsuariosRepository usuariosRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("El filtro esta siendo llamado");
        var authHeader=request.getHeader("Authorization");
//        if( token==null || token== ""){
//            throw new RuntimeException("El token enviado no es valido");
//        }
        if (authHeader!=null){
            System.out.println("Validamos que el token no es nulo");
            var token=authHeader.replace("Bearer ","");
//            System.out.println(authHeader);
//            System.out.println(tokenService.getSubject(authHeader));
            var nombreUsuario =tokenService.getSubject(token);
            if (nombreUsuario!=null) {
                var usuario=usuariosRepository.findByLogin(nombreUsuario);
                var authentication=new UsernamePasswordAuthenticationToken(usuario,null
                        ,usuario.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request,response);

    }
}
