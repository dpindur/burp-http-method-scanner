package plugin;

import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

public class HttpMethodScanIssue implements IScanIssue
{
    private String method;
    private IHttpService httpService;
    private URL url;
    private String detail;
    private String severity;

    public HttpMethodScanIssue(
        String method,
        IHttpService httpService,
        URL url
    ) {
        this.method = method;
        this.httpService = httpService;
        this.url = url;
        this.detail = "HTTP " + method + " Method is supported on this path";
        this.severity = "Information";
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return "HTTP " + method + " method supported";
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return new IHttpRequestResponse[0];
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}