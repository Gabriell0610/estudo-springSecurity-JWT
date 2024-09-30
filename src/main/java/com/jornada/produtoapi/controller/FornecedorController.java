package com.jornada.produtoapi.controller;

import com.jornada.produtoapi.dto.FornecedorDTO;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/fornecedor")
public class FornecedorController {
    public static int ID = 1;
    public static List<FornecedorDTO> FORNECEDORES = new ArrayList<>();
    static {
        FORNECEDORES.add(new FornecedorDTO(ID++, "Claudio Distribuidora", "12310"));
        FORNECEDORES.add(new FornecedorDTO(ID++, "Feira do Fernando", "45610"));
        FORNECEDORES.add(new FornecedorDTO(ID++, "Mercado do Ferreira", "78910"));
    }

    @GetMapping
    public List<FornecedorDTO> listar(){
        return FORNECEDORES;
    }

    @PostMapping
    public FornecedorDTO inserir(@RequestBody FornecedorDTO fornecedorDTO){
        fornecedorDTO.setId(ID++);
        FORNECEDORES.add(fornecedorDTO);
        return fornecedorDTO;
    }
}
