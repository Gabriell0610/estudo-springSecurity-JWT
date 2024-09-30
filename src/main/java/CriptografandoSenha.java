import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CriptografandoSenha {
    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

        //String senhaCriptografada = bCryptPasswordEncoder.encode("123");
        //System.out.println(senhaCriptografada);

//        Boolean senhaCorreta = bCryptPasswordEncoder.matches("12345", "$2a$10$k8Cx/..6PiveSoXnqL74.OdoNQLw0KGYid6zpGhifxY/j/256CXFe");
//        System.out.println(senhaCorreta);
    }
}
