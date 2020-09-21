package com.aprz.javaxencryptionhook;


import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class Entry implements IXposedHookLoadPackage {

    private IXposedHookLoadPackage delegate = new JavaxEncryptionHook("com.example.testapk");


    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {
        delegate.handleLoadPackage(loadPackageParam);
    }
}
