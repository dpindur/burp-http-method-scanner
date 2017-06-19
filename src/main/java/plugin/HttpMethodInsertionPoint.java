package plugin;

import burp.IExtensionHelpers;
import burp.IScannerInsertionPoint;

public class HttpMethodInsertionPoint implements IScannerInsertionPoint
{
    public static final String NAME = "HTTP Method";

    private IExtensionHelpers helpers;
    private String baseRequest;
    private String baseMethod;

    public HttpMethodInsertionPoint(IExtensionHelpers helpers, byte[] baseRequest)
    {
        this.helpers = helpers;
        this.baseMethod = helpers.analyzeRequest(baseRequest).getMethod();
        this.baseRequest = helpers.bytesToString(baseRequest);
    }

    @Override
    public byte[] buildRequest(byte[] payload)
    {
        String newMethod = helpers.bytesToString(payload);

        // Work around to prevent this insertion point from being used for anything other
        // than HttpMethodScanner. See here for more:
        // https://support.portswigger.net/customer/portal/questions/12431820-design-of-active-scanner-plugin-vs-insertionpoints
        if (!HttpMethodScanner.METHODS.contains(newMethod)) {
            return helpers.stringToBytes(baseRequest);
        }

        String newRequest = baseRequest.replaceFirst(baseMethod, newMethod);
        return helpers.stringToBytes(newRequest);
    }

    @Override
    public String getBaseValue()
    {
        return baseMethod;
    }

    @Override
    public int[] getPayloadOffsets(byte[] payload)
    {
        return null;
    }

    @Override
    public String getInsertionPointName()
    {
        return NAME;
    }

    @Override
    public byte getInsertionPointType()
    {
        return INS_EXTENSION_PROVIDED;
    }
}