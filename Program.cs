using Microsoft.Extensions.Logging;
using Serilog;
using sslanalyze.Services;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.Console()
    .WriteTo.File("logs/sslanalyze-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30)
    .CreateLogger();

using var loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddSerilog(dispose: false);
});

ILogger<Program> logger = loggerFactory.CreateLogger<Program>();

try
{
    if (args.Length == 0)
    {
        Console.WriteLine("Usage: sslanalyze <path-to-sslyze-json>");
        return;
    }

    logger.LogInformation("sslanalyze starting");

    var parser = new SSLyzeParser(loggerFactory);
    var rawJson = await File.ReadAllTextAsync(args[0]);
    var issues = await parser.ParseScanDefects(rawJson);

    foreach (var issue in issues)
    {
        logger.LogInformation(issue.QueryDescription, issue);
    }

    logger.LogInformation("sslanalyze finished");
}
catch (Exception ex)
{
    logger.LogCritical(ex, "Unhandled exception");
    throw;
}
finally
{
    Log.CloseAndFlush();
}
