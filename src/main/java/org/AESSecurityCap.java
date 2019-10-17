package org;

import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class AESSecurityCap {

  private PublicKey publickey;
  KeyAgreement keyAgreement;
  byte[] sharedsecret;

  String ALGO = "AES";

  AESSecurityCap() {
    makeKeyExchangeParams();
  }

  private void makeKeyExchangeParams() {
    KeyPairGenerator kpg = null;
    try {
      kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(128);
      KeyPair kp = kpg.generateKeyPair();
      publickey = kp.getPublic();
      keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(kp.getPrivate());

    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  public void setReceiverPublicKey(PublicKey publickey) {
    try {
      keyAgreement.doPhase(publickey, true);
      sharedsecret = keyAgreement.generateSecret();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  public String encrypt(String msg) {
    try {
      Key key = generateKey();
      Cipher c = Cipher.getInstance(ALGO);
      c.init(Cipher.ENCRYPT_MODE, key);
      byte[] encVal = c.doFinal(msg.getBytes());
      return Base64.getEncoder().encodeToString(encVal);
    } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return msg;
  }

  public String decrypt(String encryptedData) {
    try {
      Key key = generateKey();
      Cipher c = Cipher.getInstance(ALGO);
      c.init(Cipher.DECRYPT_MODE, key);
      byte[] decordedValue = Base64.getDecoder().decode(encryptedData);
      byte[] decValue = c.doFinal(decordedValue);
      return new String(decValue);
    } catch (BadPaddingException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return encryptedData;
  }

  public PublicKey getPublickey() {
    return publickey;
  }

  protected Key generateKey() {
    return new SecretKeySpec(sharedsecret, ALGO);
  }
}
