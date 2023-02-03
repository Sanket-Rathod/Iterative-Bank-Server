import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.xml.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.*;
import java.nio.charset.*;
// import jakarta.xml.bind.DatatypeConverter;
import javax.crypto.spec.IvParameterSpec;
// import javax.xml.bind
//     .DatatypeConverter;

public class client
{
    // initialize socket and input output streams
    private Socket socket            = null;
    // private DataInputStream  input   = null;
    private DataOutputStream out     = null;
    private DataInputStream in       =  null;
    private BufferedReader input = null;
    // constructor to put ip address and port
    public client(String address, int port)
    {
        // establish a connection
        // string to read message from input
        String line = "";
        String balance ="";
        try
        {
            socket = new Socket(address, port);
            System.out.println("Connected");

            // takes input from terminal
            
            input= new BufferedReader(new InputStreamReader(System.in));
            in = new DataInputStream(
                new BufferedInputStream(socket.getInputStream()));
            
            // sends output to the socket
            out    = new DataOutputStream(socket.getOutputStream());

            //fetch public key
            String publicKey = in.readUTF();
            
            // System.out.println("Public Key : " + publicKey);
            String plainText = publicKey;
            //send secret key encrypted with public key

            // SecureRandom securerandom = new SecureRandom();
            // KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
            // keygenerator.init(256, securerandom);
            // SecretKey key = keygenerator.generateKey();
            
            // System.out.println("Secret key is "+key);

            // byte[] initializationVector = new byte[16];
            // SecureRandom secureRandom = new SecureRandom(); 
            // secureRandom.nextBytes(initializationVector);

            // Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
 
            // IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
            // cipher.init(Cipher.ENCRYPT_MODE,key,ivParameterSpec);
            
            // System.out.println("Ciphered text is  : "+cipher.doFinal(plainText.getBytes()));
             
            
            SecureRandom securerandom
                = new SecureRandom();
            KeyGenerator keygenerator
                = KeyGenerator.getInstance("AES");
    
            keygenerator.init(256, securerandom);
            SecretKey Symmetrickey
                = keygenerator.generateKey();
            
            byte[] rawData = Symmetrickey.getEncoded();
            String encodedKey = Base64.getEncoder().encodeToString(rawData);
            // System.out.println("ENCODED KEY IN STRING : "+ encodedKey);
            // System.out.println(
            // "The Symmetric Key is :"
            // + DatatypeConverter.printHexBinary(
            //       Symmetrickey.getEncoded()));
    
            // byte[] initializationVector
            //     = createInitializationVector();

            byte[] initializationVector
                = new byte[16];
            SecureRandom secureRandom
                = new SecureRandom();
            secureRandom.nextBytes(initializationVector);
    
            
    
            // Encrypting the message
            // using the symmetric key
            // byte[] cipherText
            //     = do_AESEncryption(
            //         plainText,
            //         Symmetrickey,
            //         initializationVector);

            Cipher cipher
                = Cipher.getInstance(
                    "AES/CBC/PKCS5PADDING");
    
            IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                    initializationVector);
    
            cipher.init(Cipher.ENCRYPT_MODE,
                        Symmetrickey,
                        ivParameterSpec);
            
            String idPass
                = "id password";

            // System.out.println("Ciphered text for sk is : "+cipher.doFinal(
            //     idPass.getBytes()));
            
            
    
            // System.out.println(
            //     "The ciphertext or "
            //     + "Encrypted Message is: "
            //     + DatatypeConverter.printHexBinary(
            //         cipherText));
            

            String encryptedString = Base64.getEncoder().encodeToString(encrypt(encodedKey, publicKey));
            
            // String encryptedString1 = Base64.getEncoder().encodeToString(encrypt(initializationVector, publicKey));
            // System.out.println(" Encrypted String : " + encryptedString);

            out.writeUTF(encryptedString);
            // out.writeUTF(encryptedString1);
            
            String ivString = Base64.getEncoder().encodeToString(initializationVector);
            out.writeUTF(ivString);

            

            while(true){
                System.out.print("Enter Your Id : ");
                String userId = input.readLine();
                byte[] cipherTextUserId = cipher.doFinal(
                    userId.getBytes());
                String cipherTextStrId = Base64.getEncoder().encodeToString(cipherTextUserId);
                out.writeUTF(cipherTextStrId);
                // out.writeUTF(userId);
                System.out.print("Enter Your password : ");
                String password = input.readLine();
                byte[] cipherTextPasswd = cipher.doFinal(
                    password.getBytes());
                String cipherTextStrPasswd = Base64.getEncoder().encodeToString(cipherTextPasswd);
                out.writeUTF(cipherTextStrPasswd);
                // out.writeUTF(password);
                // String idPass = userId + password;
                
                if(in.readUTF().equals("1")){
                    // System.out.println("here");
                    
                    break;
                }
                else {
                    System.out.println("The Id/password is incorrect. Please try again.");
                }
            }

            
            while(true){
                balance =  (String)in.readUTF();
                System.out.println("Your account balance is " + balance+ ".");
                System.out.println("You have below options : \n1. Transfer\n2. Exit");
                System.out.println("Please select one : ");
                String action = input.readLine();
                if(action.equals("2"))break;
                else if(action.equals("1")){
                    
                    out.writeUTF("1");
                    System.out.println("Enter the ID of the recepient : ");
                    String userIdForTransfer = input.readLine();
                    out.writeUTF(userIdForTransfer);
                    System.out.println("Enter the amount to transfer money : ");
                    String amountForTransfer = input.readLine();
                    out.writeUTF(amountForTransfer);
                    String status = in.readUTF();
                    if(status.equals("0")){
                        System.out.println("Your Transaction is unsuccessful. Please try again.");
                        // out.writeUTF("1");
                    }else {
                        System.out.println("Your Transaction is successful.");
                    }
                }
                else {
                    System.out.println("You selected other than 1 or 2.");
                }
            }
    
        }
        catch(UnknownHostException u)
        {
            System.out.println(u);
        }
        catch(IOException i)
        {
            System.out.println(i);
        }
        catch(BadPaddingException b){
            System.out.println(b);
        }
        catch(NoSuchAlgorithmException n){
            System.out.println(n);
        }
        catch(Exception e){
            System.out.println(e);
        }
 
        
 
        // keep reading until "Over" is input
        // while (!line.equals("Over"))
        // {
        //     try
        //     {
        //         line = input.readLine();
        //         out.writeUTF(line);
        //     }
        //     catch(IOException i)
        //     {
        //         System.out.println(i);
        //     }
        // }
 
        // close the connection
        try
        {
            System.out.println("Exiting and closing the client.");
            if(input!=null)
            input.close();
            if(out!=null)
            out.close();
            if(socket!=null)
            socket.close();
        }
        catch(IOException i)
        {
            System.out.println(i);
        }
    }

    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
       
        return publicKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }



public class RSAUtil {

    // private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgFGVfrY4jQSoZQWWygZ83roKXWD4YeT2x2p41dGkPixe73rT2IW04glagN2vgoZoHuOPqa5and6kAmK2ujmCHu6D1auJhE2tXP+yLkpSiYMQucDKmCsWMnW9XlC5K7OSL77TXXcfvTvyZcjObEz6LIBRzs6+FqpFbUO9SJEfh6wIDAQAB";

    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    
    public static byte[] createInitializationVector()
    {
 
        // Used with encryption
        byte[] initializationVector
            = new byte[16];
        SecureRandom secureRandom
            = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }
    public static byte[] do_AESEncryption(
        String plainText,
        SecretKey secretKey,
        byte[] initializationVector)
        throws Exception
    {
        Cipher cipher
            = Cipher.getInstance(
                "AES/CBC/PKCS5PADDING");
 
        IvParameterSpec ivParameterSpec
            = new IvParameterSpec(
                initializationVector);
 
        cipher.init(Cipher.ENCRYPT_MODE,
                    secretKey,
                    ivParameterSpec);
 
        return cipher.doFinal(
            plainText.getBytes());
    }

}
    public static void main(String args[]) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException
    {
        try{
            
            String serverDomainName = args[0];
            String iaddress= InetAddress.getByName(serverDomainName).getHostAddress();
            // System.out.println(iaddress);
            int port = Integer.valueOf(args[1]);
            // System.out.println(port);
            client cli =new client(iaddress,port);
            
        }
        catch (UnknownHostException e) {
            System.out.println(e);
        }
        
        catch(Exception e){
            System.out.println(e);
        }
        
    }
}