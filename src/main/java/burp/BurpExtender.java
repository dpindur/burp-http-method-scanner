package burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

import plugin.HttpMethodInsertionPointProvider;
import plugin.HttpMethodScanner;

public class BurpExtender implements IBurpExtender
{
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName("HTTP Method Scanner");
        
        IExtensionHelpers helpers = callbacks.getHelpers();
        HttpMethodInsertionPointProvider provider = new HttpMethodInsertionPointProvider(helpers);
        HttpMethodScanner scanner = new HttpMethodScanner(helpers, callbacks);

        callbacks.registerScannerInsertionPointProvider(provider);
        callbacks.registerScannerCheck(scanner);
    }
}