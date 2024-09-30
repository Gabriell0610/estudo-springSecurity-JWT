package com.jornada.produtoapi.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FornecedorDTO {
    private Integer id;
    private String nome;
    private String cnpj;
}
