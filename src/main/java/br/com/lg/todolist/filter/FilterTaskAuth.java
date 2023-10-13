package br.com.lg.todolist.filter;

import java.io.IOException;
import java.util.Base64;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.lg.todolist.users.IUserRepository;


@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
   
        var serveletPath = request.getServletPath();
        if(serveletPath.startsWith("/tasks/")){

           var authString = new String(Base64.getDecoder().decode(request.getHeader("Authorization")
           .substring("Basic".length()).trim()));

           String[] credentials = authString.split(":");
        
           var user = this.userRepository.findByUsername(credentials[0]); 
           if(user == null ){
                response.sendError(401, "Usuário sem Autorização"); 
           }else{
                
                var passVerify = BCrypt.verifyer().verify(credentials[1].toCharArray(),user.getPassword());
                
                if(passVerify.verified){
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                }else{
                    response.sendError(401, "Senhas não conferem"); 
                }
           } 

        }else{

            filterChain.doFilter(request, response);
        }
    }
}
