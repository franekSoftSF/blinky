namespace Blinky.AdcsConnector;

/// <summary>
/// Exposes the ADCS transport contract over HTTPS and calls ICertRequest3
/// locally. Skeleton until patch 0032.
/// </summary>
public sealed class ConnectorWorker(ILogger<ConnectorWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("ADCS connector started (no CA configured)");

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}
