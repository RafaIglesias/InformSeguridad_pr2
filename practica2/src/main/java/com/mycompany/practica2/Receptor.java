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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

//import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Base64;


/**
 *
 * @author samuelmp
 */
public class Receptor {
    
    private Cipher cifradorClavePP;
    private KeyPairGenerator keyGen;
    private KeyPair parClaves;
    private PrivateKey clavePrivada;
    private PublicKey clavePublica;
    private String algoritmoSesion;
    private String algoritmoAsimetrico;
    private Cipher cifradorClaveSesion;

    public Receptor() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.algoritmoSesion = "Blowfish";
        this.algoritmoAsimetrico = "RSA";
        this.cifradorClaveSesion=Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        this.cifradorClavePP = Cipher.getInstance(this.algoritmoAsimetrico);
    }
    
    public void crearParDeClaves(int keylength) throws NoSuchAlgorithmException {
        this.keyGen = KeyPairGenerator.getInstance(this.algoritmoAsimetrico);
        this.keyGen.initialize(keylength);
        this.parClaves = this.keyGen.generateKeyPair();
        this.clavePrivada = parClaves.getPrivate();
        this.clavePublica = parClaves.getPublic();
    }

    public PrivateKey getClavePrivada() {
        return this.clavePrivada;
    }
//clave publica tipo 
    public PublicKey getClavePublica() {
        return this.clavePublica;
    }
    
    public String desencriptarConClavePrivada(String msg, PrivateKey k) throws InvalidKeyException, UnsupportedEncodingException,
                                                                IllegalBlockSizeException, BadPaddingException {
        // Completar: desencriptar el String con clave privada y devolver
        // un String con el texto desencriptado
        
        //recibe la clave privada tipo RSA obtenida del fichero para obtener la clave de sesion que es simetrica tipo Blowfish;
        //para ello el string está encriptado con la clave privada RSA q le paso a la funcion
        
        //tengo que desencriptarlo y pasar la cadena de textoplano;
        
        byte[] bytesmensajecifrado ;
        bytesmensajecifrado = msg.getBytes();
        
        cifradorClavePP.init(Cipher.DECRYPT_MODE, k);
 
        byte[] mensaje ;
        
        
        //este mensaje ahora supera el tamaño maximo para utilizar el metodo doFinal simplemente sobre el mensaje final , tengo que implementar algun tipo de division en los datos
        //o los divido el bloques o intento el outputcipherstream.
        
        
        mensaje = cifradorClavePP.doFinal(bytesmensajecifrado);
        //este mensaje es la clave tipo Blowfish simetrica
        return Base64.toBase64String(mensaje);
        

    }
    
   
    public String desencriptarConClaveSesion(String msg, SecretKey claveSesion) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException
    {
        // Completar: desencriptar el String con clave de Sesion y devolver
        // un String con el texto desencriptado
        
        //uso la clave Blowfish para desencriptar el mensaje de la criptografiamola;
        
        byte[] mensajecifrado ;
        
        mensajecifrado = msg.getBytes();
        cifradorClaveSesion.init(Cipher.DECRYPT_MODE, claveSesion);
        
        byte[] mensaje;
        
        mensaje = cifradorClaveSesion.doFinal(mensajecifrado);
        
        return Base64.toBase64String(mensaje);

    }
    
    public SecretKey crearClaveDesdeString(String claveS) throws NoSuchAlgorithmException{
        // Completar: utilizar SecretKeySpec para generar la clave de sesion
        // a partir del String de entrada. Devolver clave de Sesion como tipo SecretKey
        
        //Tengo la clave en String , la clave es tipo Blowfish simetrica, tengo que devolver la clave en SecretKey
        
        byte[] clavecifrada;
        clavecifrada = claveS.getBytes();
        
        SecretKeySpec claveregenerada = new SecretKeySpec(clavecifrada,algoritmoSesion);
        
        return claveregenerada;
        
    }
    
    public PrivateKey leerClavePrivadaDeArchivo(String nombreArchivo) throws Exception {
        // Completar: recuperar clave privada de fichero y devolverla como tipo PrivateKey
        //Este metodo es recuperar la clave privada del propio receptor que esta guardada en un archivo .
        //la clave privada es tipo asimetrico rsa;
        
        FileInputStream clavebytes = new FileInputStream(nombreArchivo);
        byte[] bytesclave;
       bytesclave = clavebytes.readAllBytes();
       //tengo en clavebytes los bytes de la clave;
      PKCS8EncodedKeySpec claveregenerada = new PKCS8EncodedKeySpec(bytesclave);
      KeyFactory conversion = KeyFactory.getInstance(algoritmoAsimetrico);
      PrivateKey clavefinal = conversion.generatePrivate(claveregenerada);
       
       return clavefinal;
       
       /*
       //Leer y descifrar el fichero encriptado con CipherInputStream. Consta de un
        //FileInputStream y un Cipher que leen los bytes del fichero y los descibran.
        FileInputStream fis;
        fis = new FileInputStream(nombreFicheroEncriptado);
        CipherInputStream in;
        in = new CipherInputStream(fis, descifrador);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int numberOfBytedRead;
        while ((numberOfBytedRead = in.read(b)) >= 0) {
                baos.write(b, 0, numberOfBytedRead);
        }
        in.close();
        fis.close(); 
       */

    }
    
    public void guardarClaveEnArchivo(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(key);
            fos.flush();
        }
    }
       
}
