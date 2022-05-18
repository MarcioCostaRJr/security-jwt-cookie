package br.com.examplejwt.cookie.model.entity;

import br.com.examplejwt.cookie.model.enums.ERole;
import lombok.Data;

import javax.persistence.*;
import java.io.Serializable;

import static javax.persistence.EnumType.STRING;
import static javax.persistence.GenerationType.IDENTITY;

@Entity
@Table(name = "roles")
@Data
public class Role implements Serializable {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    private Integer id;

    @Enumerated(STRING)
    @Column(length = 20)
    private ERole name;
}
