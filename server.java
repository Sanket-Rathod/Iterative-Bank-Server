import java.net.*;
import java.io.*;
import java.util.*;
import java.math.*;
import java.security.*;
import java.nio.file.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.SecureRandom;
import java.util.Scanner;
 
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec
    .*;

class server{
    public static String getMd5(String input)
    {
        try {
 
            // Static getInstance method is called with hashing MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
 
            // digest() method is called to calculate message digest
            // of an input digest() return array of byte
            byte[] messageDigest = md.digest(input.getBytes());
 
            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);
 
            // Convert message digest into hex value
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }
 
        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    //initialize socket and input stream
    private Socket          socket   = null;
    private ServerSocket    server   = null;
    private DataInputStream in       =  null;
    private DataOutputStream out     = null;
    // constructor with port
    public server(int port)
    {
        // starts server and waits for a connection
        try
        {
            server = new ServerSocket(port);
            System.out.println("Server started");
 
            System.out.println("Waiting for a client ..."); 
            
            while(true){
            try{
            
            socket = server.accept();
            System.out.println("Client accepted");
 
            // takes input from the client socket
            in = new DataInputStream(
                new BufferedInputStream(socket.getInputStream()));
                        // sends output to the socket
            out = new DataOutputStream(socket.getOutputStream());
            String line = "";
            String userId="";
            String balance="";
            //get secret key from client
            RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
            
            String publicKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded());
            out.writeUTF(publicKey);
            String encryptedString = (String)in.readUTF();
            // System.out.println("FETCHED ENCRYPTED STRING : "+ encryptedString);
            
            String Symmetrickey = RSAUtil.decrypt(encryptedString, privateKey);
            // System.out.println("DECRYPTED SECRET KEY : "+Symmetrickey);
            byte[] decodedKey = Base64.getDecoder().decode(Symmetrickey);
            SecretKey symKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            String ivString = (String)in.readUTF();
            byte[] initializationVector = Base64.getDecoder().decode(ivString);

            
            Cipher cipher
                = Cipher.getInstance(
                    "AES/CBC/PKCS5PADDING");
    
            IvParameterSpec ivParameterSpec
                = new IvParameterSpec(
                    initializationVector);
    
            cipher.init(
                Cipher.DECRYPT_MODE,
                symKey,
                ivParameterSpec);
            
            

            while (true)
            {
                
                try
                {
                    // out.writeUTF("send");
                    // line = (String)in.readUTF();
                    // System.out.println(line);
                    // String userId = (String)in.readUTF();
                    String cipherTextStrUserId = in.readUTF();
            
                    byte[] cipherTextId = Base64.getDecoder().decode(cipherTextStrUserId);
                    
                    byte[] result
                        = cipher.doFinal(cipherTextId);
                    
                    userId = new String(result);
                    
                    // System.out.println("DECODED userID is : "+userId);
                    String cipherTextStrPasswd= (String)in.readUTF();

                    byte[] cipherTextPasswd = Base64.getDecoder().decode(cipherTextStrPasswd);
                    
                    byte[] resultPasswd
                        = cipher.doFinal(cipherTextPasswd);
                    
                    String password = new String(resultPasswd);

                    // System.out.println("DECODED PASSWORD IS : "+password);
                    String hashedPassword = getMd5(password);
                    // System.out.println(hashedPassword);
                    // System.out.println("Working Directory = " + System.getProperty("user.dir"));
                    File passObj = new File(System.getProperty("user.dir") + "/passwd.txt");
                    FileReader fr = new FileReader(passObj);
                    BufferedReader br = new BufferedReader(fr);
                    boolean found = false;
                    while ((line = br.readLine())!=null) {
                        // System.out.println("here");
                        if( line.substring(0,userId.length()).equals(userId) && 
                            line.substring(userId.length()+1,line.length()).equals(hashedPassword)){
                            found = true;
                            System.out.println("USERID and PASSWORD matched");
                            out.writeUTF("1");
                            
                            break;
                        }
                        // System.out.println(line);
                    }

                    br.close();
                    fr.close();
                    // passObj.close();
                    if(!found){
                        out.writeUTF("0");
                        System.out.println("USERID and PASSWORD NOT matched");
                        continue;
                    }
                    else break;
                }
                //balance
                catch(IOException i)
                {
                    // continue;
                    System.out.println("Client connection closed. Waiting for new connection.");
                    break;
                }
                catch(Exception e){
                    System.out.println(e);
                }
            }

            //fetch balance
            
            //Transfer
            // String actionToBePerformed = in.readUTF();
            //loop till we received 1 from client.
            while(true){
            File balObj = new File(System.getProperty("user.dir") + "/balance.txt");
            FileReader balFR = new FileReader(balObj);
            BufferedReader balBR = new BufferedReader(balFR);
            
            while ((line = balBR.readLine())!=null) {
                
                // System.out.println("here yo");
                if( line.substring(0,userId.length()).equals(userId)){
                    // System.out.println("here");
                    balance = line.substring(userId.length()+1,line.length());
                    // System.out.println(balance);
                    out.writeUTF(balance);
                    
                    break;
                }
                // System.out.println(line);
            }
            
            balBR.close();
            balFR.close();
            if(in.readUTF().equals("1")){

            
            boolean first = true;
            

                String userIdForTransfer = (String)in.readUTF();
                String amountForTransfer = in.readUTF();
                String oldContent = "";
                
                String balance1= "";
                int amt = Integer.valueOf(amountForTransfer);
                int bal = Integer.valueOf(balance);
                File transObj = null;
                FileReader transFR = null;
                BufferedReader transBR = null;
                FileWriter fw = null;
                if(amt>bal){
                    out.writeUTF("0");
                    continue;
                    // break;
                }
                else {
                    
                    transObj = new File(System.getProperty("user.dir") + "/balance.txt");
                    transFR = new FileReader(transObj);
                    transBR = new BufferedReader(transFR);
                    
                    // System.out.println("here inside");
                    while ((line = transBR.readLine())!=null) {
                        // System.out.println("here yo1");
                        oldContent = oldContent + line + System.lineSeparator();
                        if( line.substring(0,userId.length()).equals(userId)){
                            // System.out.println("here1");
                            balance = line.substring(userId.length()+1,line.length());
                            // System.out.println("BALABCE : "+balance);
                            String newBalance = Integer.toString((bal-amt));
                            oldContent = oldContent.replaceAll(userId + " " + balance,userId + " " + newBalance);
                            balance = newBalance;
                        }
                        // System.out.println("here yo2");
                        if( line.substring(0,userIdForTransfer.length()).equals(userIdForTransfer)){
                            // System.out.println("here yo1");
                            balance1 = line.substring(userIdForTransfer.length()+1,line.length());
                            int bal1 = Integer.valueOf(balance1);
                            // System.out.println(balance1);
                            String newBalance1 = Integer.toString((bal1+amt));
                            oldContent = oldContent.replaceAll(userIdForTransfer + " " + balance1,userIdForTransfer + " " + newBalance1);
                            // System.out.println("UPDATED : "+oldContent);
                            
                        }

                        // System.out.println(line);
                    }
                    fw = new FileWriter(System.getProperty("user.dir") + "/balance.txt");
                    fw.append(oldContent);
                    fw.flush();
                    // System.out.println("FINAL UPDATE : "+oldContent);
                    out.writeUTF("1");
                    // out.writeUTF(balance);
                    
                }
                try{
                    if(transBR!=null)transBR.close();
                if(transFR!=null)transFR.close();
                if(fw!=null)fw.close();
                
                }
                catch(IOException i)
                {
                    System.out.println("p :"+i);
                }
                

            }
            else {
                break;
            }
            }
            //will reach here when option selected is not 1. which is 2 and exit.
            if(in!=null)in.close();
            if(out!=null)out.close();
            if(socket!=null)socket.close();
            }
            catch(IOException i)
            {
                // System.out.println("")
                continue;
                // System.out.println("HERE : "+i);
            }
            catch(Exception e){
                System.out.println(e);
            }
            }
            
            
            
            // System.out.println("Closing connection");
 
            // // close connection
            // socket.close();
            // in.close();
            

            
        }
        catch(IOException i)
        {
            
            System.out.println(i);
        }
        catch(Exception e){
            System.out.println(e);
        }
    }


    public static class RSAKeyPairGenerator {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    }

    public class RSAUtil {
        // private static String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKAUZV+tjiNBKhlBZbKBnzeugpdYPhh5PbHanjV0aQ+LF7vetPYhbTiCVqA3a+Chmge44+prlqd3qQCYra6OYIe7oPVq4mETa1c/7IuSlKJgxC5wMqYKxYydb1eULkrs5IvvtNddx+9O/JlyM5sTPosgFHOzr4WqkVtQ71IkR+HrAgMBAAECgYAkQLo8kteP0GAyXAcmCAkA2Tql/8wASuTX9ITD4lsws/VqDKO64hMUKyBnJGX/91kkypCDNF5oCsdxZSJgV8owViYWZPnbvEcNqLtqgs7nj1UHuX9S5yYIPGN/mHL6OJJ7sosOd6rqdpg6JRRkAKUV+tmN/7Gh0+GFXM+ug6mgwQJBAO9/+CWpCAVoGxCA+YsTMb82fTOmGYMkZOAfQsvIV2v6DC8eJrSa+c0yCOTa3tirlCkhBfB08f8U2iEPS+Gu3bECQQCrG7O0gYmFL2RX1O+37ovyyHTbst4s4xbLW4jLzbSoimL235lCdIC+fllEEP96wPAiqo6dzmdH8KsGmVozsVRbAkB0ME8AZjp/9Pt8TDXD5LHzo8mlruUdnCBcIo5TMoRG2+3hRe1dHPonNCjgbdZCoyqjsWOiPfnQ2Brigvs7J4xhAkBGRiZUKC92x7QKbqXVgN9xYuq7oIanIM0nz/wq190uq0dh5Qtow7hshC/dSK3kmIEHe8z++tpoLWvQVgM538apAkBoSNfaTkDZhFavuiVl6L8cWCoDcJBItip8wKQhXwHp0O3HLg10OEd14M58ooNfpgt+8D8/8/2OOFaR0HzA+2Dm";
        public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
     public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }
    public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
    }
    }
     // Driver code
    public static void main(String args[]) throws NoSuchAlgorithmException,IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException 
    {
        int port = Integer.valueOf(args[0]);
        String s = "9012";
        try{
        
        server serv = new server(port);

        // System.out.println("String is "+s+". Your HashCode Generated by MD5 is: " + getMd5(s));
        }
        catch(Exception e){
            System.out.println(e);
        }
    }
}