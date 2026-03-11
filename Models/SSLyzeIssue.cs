namespace sslanalyze.Models;

public class SSLyzeIssue
{
    public string ResultId { get; set; } = string.Empty;
    public string QueryName { get; set; } = string.Empty;
    public string QueryDescription { get; set; } = string.Empty;
    //public ScanDefectSeverity Severity { get; set; } = ScanDefectSeverity.None;
    //public ScanDefectDisposition Disposition { get; set; } = ScanDefectDisposition.New;
    public bool Suppressed { get; set; }
    public List<string> Evidence { get; set; } = new();

    public DateTime? Created { get; set; }
    public DateTime? Updated { get; set; }
}
