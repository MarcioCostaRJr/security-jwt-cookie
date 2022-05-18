package br.com.examplejwt.cookie.service.impl;

import br.com.examplejwt.cookie.model.entity.User;
import br.com.examplejwt.cookie.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Responsável por implementar conceito de criar os detalhes do usuário através de uma string (nome do usuário), a
 * obtenção é feita em conjunto com a base de dados. Provendo conceitos de interface: {@link UserDetailsService}
 *
 * @author Marcio
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final UserDetailsImpl userDetails;

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        final User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: ".concat(username)));

        return userDetails.build(user);
    }
}
