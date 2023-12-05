/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.practica2;

/**
 *
 * @author Usuario
 */
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
//import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author samuelmp
 */
public class EnvioClaveSesion {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
                                            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
                                            IOException, GeneralSecurityException, Exception {

        //Instanciamos las clases para el emisor y receptor
        Receptor receptor = new Receptor();
        Emisor emisor = new Emisor();

        //El receptor genera el par de claves publica y privada
        receptor.crearParDeClaves(1024);
        
        //El receptor almacena ambas claves en archivo. Simulamos la "publicacion" de la clave
        //pública guardandola en la carpeta del emisor tambien
        
        //las claves publicas y privadas son tipo asimetricas tipo rsa
        receptor.guardarClaveEnArchivo("archivosReceptor/clavePrivada", receptor.getClavePrivada().getEncoded());
        receptor.guardarClaveEnArchivo("archivosReceptor/clavePublica", receptor.getClavePublica().getEncoded());
        receptor.guardarClaveEnArchivo("archivosEmisor/clavePublica", receptor.getClavePublica().getEncoded());
        
        //El emisor crea la clave de sesion
        //la clave de sesion es tipo simetrica usando Blowfish
        emisor.crearClaveSimetrica();
        SecretKey claveSesion = emisor.getClaveSimetrica();
      
        
        //El emisor recupera la clave publica de archivo
        
        PublicKey clavePublica = emisor.leerClavePublicaDeArchivo("archivosEmisor/clavePublica");
        //hecho
                                    
        //El emisor encripta la clave de sesion con la clave publica
        //Codifica la clave Blowfish usando la publica RSA
        String claveSesionS = Base64.toBase64String(claveSesion.getEncoded());
        String claveSesionEncriptada = emisor.encriptarConClavePublica(claveSesionS, clavePublica);    
        //hecho
        //El emisor crea el mensaje y lo encripta con la clave de sesion
        String msg = "¡La criptografía es divertida!";
        String textoCifrado = emisor.encriptarConClaveSesion(msg, claveSesion);
        //hecho
        
       
        // -------- Emisor envia (mensaje + clave de sesion) ...... --------------//
        // ...........
        // ......
        // -------- ... receptor recibe (mensaje + clave de sesion) --------------//
        
        //El receptor recupera su clave privada        
        PrivateKey clavePrivada = receptor.leerClavePrivadaDeArchivo("archivosReceptor/clavePrivada");
        //hecho
        
        
        //El receptor usa su clave privada para desencriptar la clave de sesion
        //pera por ttipo de cifrador , no puedo hacer un doFinal porq size>Max, flujo ? bloque? 
        String claveSesionDesencriptadaS = receptor.desencriptarConClavePrivada(claveSesionEncriptada, clavePrivada);
        //hecho
        SecretKey claveSesionDesencriptada = receptor.crearClaveDesdeString(claveSesionDesencriptadaS);
        //hecho
        //El receptor desencripta el mensaje con la clave de sesion
        String textoDesencriptado = receptor.desencriptarConClaveSesion(textoCifrado, claveSesionDesencriptada);
        //hecho
        
        //Imprimir las claves y los mensajes para comprobar que funciona correctamente
        System.out.println("la clave de sesion generada es: " + claveSesionS);
        System.out.println("la clave de sesion recuperada es: " + claveSesionDesencriptadaS);        
        
        System.out.println("\nMensaje original: " + msg  + "\nMensaje desencriptado: " + textoDesencriptado + "\n");
        

    }
    
}
