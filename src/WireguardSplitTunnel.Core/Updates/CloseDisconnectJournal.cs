using System.Text.Json;
using System.Text.Json.Serialization;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Updates;

public enum CloseDisconnectJournalPhase
{
    WaitingForEnable,
    TargetsRecorded
}

public sealed record CloseDisconnectJournalEntry(
    Guid OperationId,
    CloseDisconnectJournalPhase Phase,
    IReadOnlyList<WindowsTunnelServiceIdentity> Targets,
    WindowsTunnelServiceIdentity? PendingEnable,
    EnableTunnelProcessIdentity? PendingEnableProcess = null);

public interface ICloseDisconnectJournal
{
    CloseDisconnectJournalEntry? Load();
    void Save(CloseDisconnectJournalEntry entry);
    void Complete(Guid operationId);
}

public sealed class FileCloseDisconnectJournal : ICloseDisconnectJournal
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly string filePath;

    public FileCloseDisconnectJournal(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);
        this.filePath = filePath;
    }

    public CloseDisconnectJournalEntry? Load()
    {
        using var lockStream = AcquireLock();
        return LoadCore();
    }

    public void Save(CloseDisconnectJournalEntry entry)
    {
        if (entry is null)
        {
            throw new InvalidDataException("Close-disconnect journal entry is required.");
        }

        var targetNames = entry.Targets?.Select(target => target?.ServiceName!).ToArray();
        var pendingEnableName = entry.PendingEnable?.ServiceName;
        Validate(
            entry.OperationId,
            entry.Phase,
            targetNames,
            pendingEnableName,
            entry.PendingEnableProcess);

        using var lockStream = AcquireLock();
        var directory = Path.GetDirectoryName(filePath);
        var tempFilePath = Path.Combine(
            directory ?? string.Empty,
            $".{Path.GetFileName(filePath)}.{Guid.NewGuid():N}.tmp");

        try
        {
            var data = new JournalData
            {
                OperationId = entry.OperationId,
                Phase = entry.Phase,
                Targets = targetNames,
                PendingEnable = pendingEnableName,
                PendingEnableProcess = entry.PendingEnableProcess
            };
            var json = JsonSerializer.Serialize(data, JsonOptions);
            File.WriteAllText(tempFilePath, json);

            // Cooperating processes hold the same lock, so the destination cannot
            // change between this check and the atomic publication operation.
            if (File.Exists(filePath))
            {
                File.Replace(tempFilePath, filePath, destinationBackupFileName: null);
            }
            else
            {
                File.Move(tempFilePath, filePath);
            }
        }
        finally
        {
            try
            {
                File.Delete(tempFilePath);
            }
            catch
            {
                // Cleanup is best effort and must not mask a publication failure.
            }
        }
    }

    public void Complete(Guid operationId)
    {
        if (operationId == Guid.Empty)
        {
            throw new InvalidDataException("Close-disconnect operation ID must not be empty.");
        }

        using var lockStream = AcquireLock();
        var entry = LoadCore();
        if (entry is null || entry.OperationId != operationId)
        {
            return;
        }

        // The ID is revalidated while the same cross-process lock is still held.
        File.Delete(filePath);
    }

    private CloseDisconnectJournalEntry? LoadCore()
    {
        if (!File.Exists(filePath))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(filePath);
            var data = JsonSerializer.Deserialize<JournalData>(json, JsonOptions);
            if (data is null)
            {
                throw new InvalidDataException($"Close-disconnect journal '{filePath}' is empty or null.");
            }

            Validate(
                data.OperationId,
                data.Phase,
                data.Targets,
                data.PendingEnable,
                data.PendingEnableProcess);
            return new CloseDisconnectJournalEntry(
                data.OperationId,
                data.Phase,
                data.Targets!
                    .Select(name => WindowsTunnelServiceIdentity.FromServiceName(name!))
                    .ToArray(),
                data.PendingEnable is null
                    ? null
                    : WindowsTunnelServiceIdentity.FromServiceName(data.PendingEnable),
                data.PendingEnableProcess);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                $"Close-disconnect journal '{filePath}' contains invalid JSON.",
                ex);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidDataException(
                $"Close-disconnect journal '{filePath}' contains an invalid service identity.",
                ex);
        }
    }

    private FileStream AcquireLock()
    {
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // This empty artifact is deliberately never deleted. A stable lock file
        // prevents a delete/recreate race from separating concurrent lock holders.
        while (true)
        {
            try
            {
                return new FileStream(
                    filePath + ".lock",
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None);
            }
            catch (IOException ex) when ((ex.HResult & 0xFFFF) is 32 or 33)
            {
                // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION: the operating
                // system releases this lock even if the owning process exits.
                Thread.Sleep(10);
            }
        }
    }

    private static void Validate(
        Guid operationId,
        CloseDisconnectJournalPhase phase,
        IReadOnlyList<string?>? targets,
        string? pendingEnable,
        EnableTunnelProcessIdentity? pendingEnableProcess)
    {
        if (operationId == Guid.Empty)
        {
            throw new InvalidDataException("Close-disconnect operation ID must not be empty.");
        }

        if (!Enum.IsDefined(phase))
        {
            throw new InvalidDataException("Close-disconnect journal phase is undefined.");
        }

        if (targets is null)
        {
            throw new InvalidDataException("Close-disconnect journal targets are required.");
        }

        foreach (var target in targets)
        {
            ValidateServiceName(target);
        }

        if (pendingEnable is not null)
        {
            ValidateServiceName(pendingEnable);
        }

        if (pendingEnableProcess is not null
            && (pendingEnable is null
                || pendingEnableProcess.ProcessId <= 0
                || pendingEnableProcess.CreationTimeFileTimeUtc <= 0))
        {
            throw new InvalidDataException(
                "Close-disconnect journal contains an invalid pending process identity.");
        }
    }

    private static void ValidateServiceName(string? serviceName)
    {
        try
        {
            WindowsTunnelServiceIdentity.FromServiceName(serviceName!);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidDataException(
                "Close-disconnect journal contains an invalid service identity.",
                ex);
        }
    }

    private sealed class JournalData
    {
        public required Guid OperationId { get; init; }

        public required CloseDisconnectJournalPhase Phase { get; init; }

        public required string?[]? Targets { get; init; }

        public string? PendingEnable { get; init; }

        public EnableTunnelProcessIdentity? PendingEnableProcess { get; init; }
    }
}
