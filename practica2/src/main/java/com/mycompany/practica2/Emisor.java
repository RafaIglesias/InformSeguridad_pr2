/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.practica2;

/**
 *
 * @author Usuario
 */


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
//import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author samuelmp
 */
public class Emisor {
    private PBEKeySpec pks;
    private SecretKeyFactory skf;
    private SecretKey clave;
    private String algoritmoSesion;
    private String algoritmoAsimetrico;
    private Cipher cifradorClaveSesion;
    private Cipher cifradorClavePP;
    
    public Emisor() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException {
        this.algoritmoSesion = "Blowfish";
        this.algoritmoAsimetrico = "RSA";
        //cifrador simetrico
        this.cifradorClaveSesion=Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        
        //cifrador asimetrico
        this.cifradorClavePP=Cipher.getInstance(this.algoritmoAsimetrico);
    }
        
    public void crearClaveSimetrica() throws NoSuchAlgorithmException, InvalidKeySpecException{
        this.clave = KeyGenerator.getInstance(this.algoritmoSesion).generateKey();
    }
        
    public SecretKey getClaveSimetrica(){
        return this.clave;
    }
    
    public PublicKey leerClavePublicaDeArchivo(String nombreArchivo) throws Exception {
        // Completar: recuperar la clave publica del fichero
        FileInputStream clavebytes = new FileInputStream(nombreArchivo);
        byte[] bytesclave ;
       
       bytesclave = clavebytes.readAllBytes();
       //tengo en clavebytes los bytes de la clave;
      X509EncodedKeySpec claveregenerada = new X509EncodedKeySpec(bytesclave);
      KeyFactory conversion = KeyFactory.getInstance(algoritmoAsimetrico);
      PublicKey clavefinal = conversion.generatePublic(claveregenerada);
       
       return clavefinal;
        

    }
            
    public String encriptarConClavePublica(String msg, PublicKey clavePublica) throws NoSuchAlgorithmException, NoSuchPaddingException,
        UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Completar: encriptar el String con clave publica y devolver
        // un String con el texto encriptado
        //se me pasa un string que es la clave de sesion blowfish y la clave con la que lo tengo que codificar , que es la publica RSA tengo que devolver el string, no los bytes.
        cifradorClavePP.init(Cipher.ENCRYPT_MODE, clavePublica);
        byte[] bytesmensaje;
        bytesmensaje= msg.getBytes();
        byte[] bytescifrados;
        
        //obtengo los bytes del string pasado
        //cifro los bytes y les hago un cast a String en base 64 usando la expresion que habia en el ejercicio 
        bytescifrados = cifradorClavePP.doFinal(bytesmensaje);
        
        return Base64.toBase64String(bytescifrados);
        
        
    }

    public String encriptarConClaveSesion(String msg, SecretKey claveSesion) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
    {
        // Completar: encriptar texto con la clave de sesion y devolver
        // un String con el texto encriptado
        //tengo que utilizar mi clave Blowfish simetrica para cifrar un String con una frase.
        
        cifradorClaveSesion.init(Cipher.ENCRYPT_MODE,claveSesion );
        //creo el cifrador , cojo los bytes , uso el cifrador en los bytes guardandolos, y les hago un cast a base 64 que vi anteriormente para devolverlo como String.
        byte[] bytestexto ;
        bytestexto = msg.getBytes();
        byte[] bytescifrados;
        bytescifrados = cifradorClaveSesion.doFinal(bytestexto);
      
        //en teoria si funciona 
        
        return Base64.toBase64String(bytescifrados);
        

    }
        
}
