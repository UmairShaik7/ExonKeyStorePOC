package com.example.umshaik.keystorepoc;

import android.content.Context;
import android.content.DialogInterface;
import android.security.KeyPairGeneratorSpec;
import android.support.v7.app.AlertDialog;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

public final class Utils {


    public static final String alias = "MDTA";
    private static final String androidKeyStore = "AndroidKeyStore";
    private static final String passwordKey = "password";
    private static KeyStore.PasswordProtection protParam;

    public static KeyStore InitializeKeyStore(KeyStore keyStore) throws Exception {
        keyStore = KeyStore.getInstance(androidKeyStore);
        keyStore.load(null);
        protParam =
                new KeyStore.PasswordProtection(passwordKey.toCharArray());
        return keyStore;
    }

    public static void createNewKeys(String aliasText, Context context, KeyStore keyStore) throws Exception {


        // Create new key if needed
        if (!keyStore.containsAlias(alias)) {
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);//valid for 25 years
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(spec);

            KeyPair keyPair = generator.generateKeyPair();
        }

    }

    public static KeyStore deleteKey(final Context context, final KeyStore keyStore) throws Exception {
        AlertDialog alertDialog = new AlertDialog.Builder(context)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"" + alias + "\" from the keystore?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {

                        try {
                            keyStore.deleteEntry(alias);

                        } catch (KeyStoreException e) {
                            e.printStackTrace();
                        }
                        // refreshKeys();

                        dialog.dismiss();
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .create();
        alertDialog.show();
        return keyStore;
    }

    public static String encryptString(String textToEncrypt, KeyStore keyStore) throws Exception {

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protParam);
        RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

        String initialText = textToEncrypt;
           /* if(initialText.isEmpty()) {
                Toast.makeText(this, "Enter text in the 'Initial Text' widget", Toast.LENGTH_LONG).show();
                return;
            }*/

        Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidKeyStoreBCWorkaround");
        inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(
                outputStream, inCipher);
        cipherOutputStream.write(initialText.getBytes("UTF-8"));
        cipherOutputStream.close();

        byte[] vals = outputStream.toByteArray();
        return Base64.encodeToString(vals, Base64.DEFAULT);

    }

    public static String decryptString(String textToDecrypt, KeyStore keyStore) throws Exception {
       /**/

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, protParam);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidKeyStoreBCWorkaround");
        output.init(Cipher.DECRYPT_MODE, privateKey);

        String cipherText = textToDecrypt;
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i).byteValue();
        }

        String finalText = new String(bytes, 0, bytes.length, "UTF-8");
        return finalText;

    }
}
