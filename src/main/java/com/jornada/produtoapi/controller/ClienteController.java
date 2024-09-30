package com.jornada.produtoapi.controller;


import com.jornada.produtoapi.dto.ClienteDTO;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/cliente")
public class ClienteController {
    public static int ID = 1;
    public static List<ClienteDTO> CLIENTES = new ArrayList<>();
    static {
        CLIENTES.add(new ClienteDTO(ID++, "Maicon", "123"));
        CLIENTES.add(new ClienteDTO(ID++, "Fernando", "456"));
        CLIENTES.add(new ClienteDTO(ID++, "Paulo", "789"));
    }

    @GetMapping
    public List<ClienteDTO> listar(){
        return CLIENTES;
    }

    @PostMapping
    public ClienteDTO inserir(@RequestBody ClienteDTO clienteDTO){
        clienteDTO.setId(ID++);
        CLIENTES.add(clienteDTO);
        return clienteDTO;
    }
}
