package br.com.examplejwt.cookie.model.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserInfoResponse implements Serializable {

    private Long id;
    private String username;
    private String email;
    private List<String> roles;
}
