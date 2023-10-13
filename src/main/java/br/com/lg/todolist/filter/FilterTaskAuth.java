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
import br.com.lg.todolist.utils.Utils;


@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
   
        var serveletPath = request.getServletPath();
        if(serveletPath.startsWith("/tasks/")){

           var authorization = request.getHeader("Authorization");
           var user_passEncoded = authorization.substring("Basic".length()).trim(); 
           byte[] user_passDecoded = Base64.getDecoder().decode(user_passEncoded); 

           var authString = new String(user_passDecoded);
           String[] credentials = authString.split(":");
           String username = credentials[0];
           String password = credentials[1]; 
           var userNoQuotes = Utils.removeDoubleQuotes(username);
           var user = this.userRepository.findByUsername(userNoQuotes);

            if(user == null ){
                response.sendError(401, "Usuário sem Autorização"); 
           }else{
                var passVerify = BCrypt.verifyer().verify(password.toCharArray(),user.getPassword());
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
