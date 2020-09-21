package com.aprz.javaxencryptionhook;


import android.util.Log;

import androidx.annotation.NonNull;


import java.security.MessageDigest;

import javax.crypto.Cipher;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

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

            hookIv(loadPackageParam);

            hookSecretKeySpec(loadPackageParam);

            hookDESedeKeySpec(loadPackageParam);

            hookDESKeySpec(loadPackageParam);

            hookCipher(loadPackageParam);
        }

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

                        Log.e(TAG, String.format("算法名称是：%s，iv是%s, 结果是%s", algorithm,
                                HexDumper.dumpHexString(iv), HexDumper.dumpHexString(result)));

                        FileUtils.log(loadPackageParam.packageName,
                                String.format("算法名称是：%s，其他信息如下：", algorithm), iv, result, new Throwable());
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
                if (param.args.length != 1) //如果有两个参数的构造函数，第二个参数是偏移
                    offset = (int) param.args[1];
                System.arraycopy((byte[]) param.args[0], offset, keyByte, 0, 8);

                Log.e(TAG, String.format("DES 密钥为 %s", HexDumper.dumpHexString(keyByte)));

                FileUtils.log(loadPackageParam.packageName, "DES密钥信息如下：", keyByte, new Throwable());
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
                if (param.args.length != 1) //如果有两个参数的构造函数，第二个参数是偏移
                    offset = (int) param.args[1];
                System.arraycopy((byte[]) param.args[0], offset, keyByte, 0, 24);

                Log.e(TAG, String.format("DES-EDE密钥为 %s", HexDumper.dumpHexString(keyByte)));

                FileUtils.log(loadPackageParam.packageName, "DES密钥信息如下：", keyByte, new Throwable());
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

                String msg = String.format("SecretKeySpec 是 %s，算法名称是：%s", HexDumper.dumpHexString(data), algorithm);
                Log.e(TAG, msg);

                FileUtils.log(loadPackageParam.packageName, String.format("算法名称是%s，SecretKeySpec 其他信息如下：", algorithm), data, new Throwable());
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

                String msg = String.format("iv向量是 %s", HexDumper.dumpHexString(ivByte));
                Log.e(TAG, msg);

                FileUtils.log(loadPackageParam.packageName, "iv向量信息如下：", ivByte, new Throwable());
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
                String msg = String.format("算法名称为：%s，加密后的数据（HEX）为：%s",
                        md.getAlgorithm(), HexDumper.dumpHexString(result));
                Log.e(TAG, msg, new Throwable("Hook 消息摘要算法"));
                FileUtils.log(loadPackageParam.packageName, String.format("摘要算法名称为：%s，其他信息如下：", md.getAlgorithm()), result, new Throwable());
            }
        });
    }
}
