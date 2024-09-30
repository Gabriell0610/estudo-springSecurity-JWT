package com.jornada.produtoapi.controller;

import com.jornada.produtoapi.dto.ProdutoDTO;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/produto")
public class ProdutoController {
    public static int ID = 1;
    public static List<ProdutoDTO> PRODUTOS = new ArrayList<>();
    static {
        PRODUTOS.add(new ProdutoDTO(ID++, "Arroz", 1.5));
        PRODUTOS.add(new ProdutoDTO(ID++, "Feijão", 2.0));
        PRODUTOS.add( new ProdutoDTO(ID++, "Batata", 2.0));
    }

    @GetMapping
    public List<ProdutoDTO> listar(){
        return PRODUTOS;
    }

    @PostMapping
    public ProdutoDTO inserir(@RequestBody ProdutoDTO produtoDTO){
        produtoDTO.setId(ID++);
        PRODUTOS.add(produtoDTO);
        return produtoDTO;
    }
}
