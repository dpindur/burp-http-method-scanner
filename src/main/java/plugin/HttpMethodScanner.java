package plugin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;

public class HttpMethodScanner implements IScannerCheck
{
    public static final List<String> METHODS = Arrays.asList(
        "PUT"
    );

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    public HttpMethodScanner(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks)
    {
        this.helpers = helpers;
        this.callbacks = callbacks;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
        {
            return -1;
        } else {
            return 0;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        if (insertionPoint.getInsertionPointName() != HttpMethodInsertionPoint.NAME)
        {
            return new ArrayList<IScanIssue>();
        }

        List<IScanIssue> issues = new ArrayList<>();

        for (String method : METHODS) {
            byte[] request = insertionPoint.buildRequest(helpers.stringToBytes(method));
            IHttpRequestResponse response = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);
            if (hasSuccessfulStatusCode(response))
            {
                IScanIssue issue = new HttpMethodScanIssue(
                    method,
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl()
                );
                issues.add(issue);
            }
        }

        return issues;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        List<IScanIssue> issues = new ArrayList<>();
        String method = helpers.analyzeRequest(baseRequestResponse).getMethod();

        if (METHODS.contains(method) && hasSuccessfulStatusCode(baseRequestResponse)) {
            IScanIssue issue = new HttpMethodScanIssue(
                method,
                baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl()
            );
            issues.add(issue);
        }

        return issues;
    }

    private Boolean hasSuccessfulStatusCode(IHttpRequestResponse requestResponse)
    {
        short statusCode = helpers.analyzeResponse(requestResponse.getResponse()).getStatusCode();
        return (statusCode >= 200 && statusCode <= 299) ||
               (statusCode >= 300 && statusCode <= 399) ||
               (statusCode == 400);
    }
}