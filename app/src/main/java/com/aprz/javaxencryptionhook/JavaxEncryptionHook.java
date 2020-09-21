package com.aprz.javaxencryptionhook;


import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;


import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.Mac;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static android.util.Base64.DEFAULT;

public class JavaxEncryptionHook implements IXposedHookLoadPackage {

    private static final String TAG = "JavaxEncryptionHook";

    public static final String ALL_PACKAGES = "all_packages";

    private String packageName;

    public JavaxEncryptionHook(@NonNull String packageName) {
        this.packageName = packageName;
    }


    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {

        // 只 hook 指定进程
        if (ALL_PACKAGES.equals(packageName) || loadPackageParam.packageName.equals(packageName)) {
            hookDigest(loadPackageParam);

            hookMac(loadPackageParam);

            hookIv(loadPackageParam);

            hookSecretKeySpec(loadPackageParam);

            hookDESedeKeySpec(loadPackageParam);

            hookDESKeySpec(loadPackageParam);

            hookCipher(loadPackageParam);

            hookKeyFactory(loadPackageParam);
            hookX509EncodedKeySpec(loadPackageParam);
        }

    }

    private void hookX509EncodedKeySpec(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllConstructors(XposedHelpers.findClass("java.security.spec.X509EncodedKeySpec", loadPackageParam.classLoader),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                        byte[] result = (byte[]) param.getResult();
                        String msg = format(result);
                        Throwable stack = new Throwable("java.security.spec.X509EncodedKeySpec#<init>");
                        Log.e(TAG, msg, stack);
                        FileUtils.log(loadPackageParam.packageName, msg, result, stack);
                    }
                });
    }

    private void hookKeyFactory(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllMethods(XposedHelpers.findClass("java.security.KeyFactory", loadPackageParam.classLoader),
                "generatePublic", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                        byte[] result = (byte[]) param.getResult();
                        String msg = format(result);
                        Throwable stack = new Throwable("java.security.KeyFactory#generatePublic");
                        Log.e(TAG, msg, stack);
                        FileUtils.log(loadPackageParam.packageName, msg, result, stack);
                    }
                });
    }

    private void hookMac(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Mac", loadPackageParam.classLoader),
                "doFinal", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                        Mac mac = (Mac) param.thisObject;
                        String algorithm = mac.getAlgorithm();
                        byte[] result = (byte[]) param.getResult();

                        String msg = format(algorithm, result);
                        Throwable stack = new Throwable("javax.crypto.Mac#doFinal");
                        Log.e(TAG, msg, stack);
                        FileUtils.log(loadPackageParam.packageName, msg, result, stack);
                    }
                });
    }


    private void hookCipher(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllMethods(XposedHelpers.findClass("javax.crypto.Cipher", loadPackageParam.classLoader),
                "doFinal", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);

                        Cipher cip = (Cipher) param.thisObject;
                        byte[] result = (byte[]) param.getResult();
                        byte[] iv = cip.getIV();
                        String algorithm = cip.getAlgorithm();

                        Throwable stack = new Throwable("javax.crypto.Cipher#doFinal");
                        String msg = format(algorithm, iv, result);
                        Log.e(TAG, msg, stack);
                        FileUtils.log(loadPackageParam.packageName, msg, iv, result, new Throwable());
                    }
                });
    }

    private void hookDESKeySpec(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllConstructors(XposedHelpers.findClass(
                "javax.crypto.spec.DESKeySpec", loadPackageParam.classLoader), new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] keyByte = new byte[8];
                int offset = 0;

                // 拷贝数据
                if (param.args.length != 1) {
                    //如果有两个参数的构造函数，第二个参数是偏移
                    offset = (int) param.args[1];
                }
                System.arraycopy((byte[]) param.args[0], offset, keyByte, 0, 8);

                String msg = format(keyByte);
                Throwable stack = new Throwable("javax.crypto.spec.DESKeySpec#<init>");
                Log.e(TAG, msg, stack);
                FileUtils.log(loadPackageParam.packageName, msg, keyByte, stack);
            }
        });
    }

    private void hookDESedeKeySpec(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllConstructors(XposedHelpers.findClass(
                "javax.crypto.spec.DESedeKeySpec", loadPackageParam.classLoader), new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] keyByte = new byte[24];
                int offset = 0;

                // 拷贝数据
                if (param.args.length != 1) {
                    //如果有两个参数的构造函数，第二个参数是偏移
                    offset = (int) param.args[1];
                }
                System.arraycopy((byte[]) param.args[0], offset, keyByte, 0, 24);

                String msg = format(keyByte);
                Throwable stack = new Throwable("javax.crypto.spec.DESedeKeySpec#<init>");

                Log.e(TAG, msg, stack);
                FileUtils.log(loadPackageParam.packageName, msg, keyByte, stack);
            }
        });
    }


    private void hookSecretKeySpec(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllConstructors(XposedHelpers.findClass(
                "javax.crypto.spec.SecretKeySpec", loadPackageParam.classLoader), new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);

                int offset = 0;
                int size = 0;
                String algorithm;

                if (param.args.length != 2) {
                    offset = (int) param.args[1];
                    size = (int) param.args[2];
                    algorithm = (String) param.args[3];
                } else {
                    algorithm = (String) param.args[1];
                    size = ((byte[]) param.args[0]).length;
                }

                byte[] data = new byte[size];
                System.arraycopy((byte[]) param.args[0], offset, data, 0, size);

                String msg = format(algorithm, data);
                Throwable stack = new Throwable("javax.crypto.spec.SecretKeySpec#<init>");

                Log.e(TAG, msg, stack);
                FileUtils.log(loadPackageParam.packageName, msg, data, stack);
            }
        });
    }

    /**
     * hook iv 向量
     */
    private void hookIv(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllConstructors(XposedHelpers.findClass(
                "javax.crypto.spec.IvParameterSpec", loadPackageParam.classLoader), new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] ivByte;
                byte[] tmp;
                int offset = 0;
                int size;
                tmp = (byte[]) param.args[0];
                size = tmp.length;
                //如果有两个参数的构造函数，第二个参数是偏移
                if (param.args.length != 1) {
                    offset = (int) param.args[1];
                    size = (int) param.args[2];
                }
                ivByte = new byte[size];
                System.arraycopy(tmp, offset, ivByte, 0, size);

                String msg = format(ivByte);
                Throwable stack = new Throwable("javax.crypto.spec.IvParameterSpec#<init>");
                Log.e(TAG, msg, stack);
                FileUtils.log(loadPackageParam.packageName, msg, ivByte, stack);
            }
        });
    }

    /**
     * hook消息摘要算法
     * 不处理 update 方法，只处理 digest 方法，获取摘要结果，然后根据堆栈去看加密的地方的源码
     */
    private void hookDigest(final XC_LoadPackage.LoadPackageParam loadPackageParam) {
        XposedBridge.hookAllMethods(XposedHelpers.findClass("java.security.MessageDigest",
                loadPackageParam.classLoader), "digest", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                MessageDigest md = (MessageDigest) param.thisObject;
                byte[] result = (byte[]) param.getResult();
                String msg = format(md.getAlgorithm(), result);
                Throwable stack = new Throwable("java.security.MessageDigest#digest");
                Log.e(TAG, msg, stack);
                FileUtils.log(loadPackageParam.packageName, msg, result, stack);
            }
        });
    }

    private static String format(String algorithm, byte[] iv, byte[] result) {
        return String.format("算法名称为：%s，\niv -> hex string ：%s，\niv -> base64 : %s, \nresult -> hex string : %s, \nresult -> base64 : %s",
                algorithm,
                HexDumper.toHexString(iv),
                Base64.encodeToString(iv, DEFAULT),
                HexDumper.toHexString(result),
                Base64.encodeToString(result, DEFAULT));
    }

    private static String format(String algorithm, byte[] result) {
        return String.format("算法名称为：%s，\nhex string ：%s，\nbase64 : %s",
                algorithm,
                HexDumper.toHexString(result),
                Base64.encodeToString(result, DEFAULT));
    }

    private static String format(byte[] result) {
        return String.format("hex string ：%s，\nbase64 : %s",
                HexDumper.toHexString(result),
                Base64.encodeToString(result, DEFAULT));
    }
}
