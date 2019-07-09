package com.securekeystore.plugin;

// Helper function for storing keys to internal storage.

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public final class KeyStorage {

    public static void writeKeyConfig(Context context, String keyAlias, int numberPart)  {
        try {
            FileOutputStream fos = context.openFileOutput(Constants.SKS_FILENAME + keyAlias + "_CONFIG", context.MODE_PRIVATE);
            Log.i(Constants.TAG, "saveKeyConfig... " + numberPart);
            fos.write(numberPart);
            fos.close();
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception saveKeyConfig: " + e.getMessage());
        }
    }

    public static int readKeyConfig(Context context, String keyAlias) {
        try {
            FileInputStream fis = context.openFileInput(Constants.SKS_FILENAME + keyAlias + "_CONFIG");
            byte[] buffer = new byte[8192];
            int bytesRead;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            byte[] cipherText = bos.toByteArray();
            String numberStr = new String(cipherText);
            Log.i(Constants.TAG, "readKeyConfig... " + numberStr);
            fis.close();
            return Integer.parseInt(numberStr);
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception readValues: "  + e.getMessage());
            return new byte[0];
        }
    }

    public static void writeValues(Context context, String keyAlias, String part, byte[] vals)  {
        try {
            FileOutputStream fos = context.openFileOutput(Constants.SKS_FILENAME + keyAlias + part, context.MODE_PRIVATE);
            String s = new String(vals);
            Log.i(Constants.TAG, "WRITEVALUES... " + s);
            fos.write(vals);
            fos.close();
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception writeValues: " + e.getMessage());
        }
    }

    public static byte[] readValues(Context context, String keyAlias, String part) {
        try {
            FileInputStream fis = context.openFileInput(Constants.SKS_FILENAME + keyAlias + part);
            byte[] buffer = new byte[8192];
            int bytesRead;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            while ((bytesRead = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, bytesRead);
            }
            byte[] cipherText = bos.toByteArray();
            String s = new String(cipherText);
            Log.i(Constants.TAG, "READVALUES... " + s);
            fis.close();
            return cipherText;
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception readValues: "  + e.getMessage());
            return new byte[0];
        }
    }

    public static void resetValues(Context context, String keyAlias)  {
        try {
            context.deleteFile(Constants.SKS_FILENAME + keyAlias + part);
        } catch (Exception e) {
            Log.e(Constants.TAG, "Exception: " + e.getMessage());
        }

    }    

}