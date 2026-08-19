namespace Blinky.Worker;

/// <summary>
/// Owns everything that must happen exactly once across the deployment: expiry
/// scanning, the job lease watchdog, CRL regeneration. Skeleton until patch
/// 0026.
/// </summary>
public sealed class LifecycleWorker(ILogger<LifecycleWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Lifecycle worker started (no scanners registered yet)");

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
        }
    }
}
