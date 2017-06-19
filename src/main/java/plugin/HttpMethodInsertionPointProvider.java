package plugin;

import java.util.ArrayList;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;

public class HttpMethodInsertionPointProvider implements IScannerInsertionPointProvider
{
    private IExtensionHelpers helpers;

    public HttpMethodInsertionPointProvider(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
    {
        IScannerInsertionPoint insertionPoint = new HttpMethodInsertionPoint(helpers, baseRequestResponse.getRequest());
        ArrayList<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
        insertionPoints.add(insertionPoint);
        return insertionPoints;
    }
}