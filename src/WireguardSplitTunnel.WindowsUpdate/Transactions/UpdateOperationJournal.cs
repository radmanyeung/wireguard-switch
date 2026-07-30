using System.Security.Cryptography;
using System.Text.Json;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Transactions;

public enum UpdateOperationKind
{
    Create,
    Replace,
    ReplaceManifest
}

public enum UpdateOperationState
{
    Planned,
    BackupStarted,
    BackupComplete,
    WriteStarted,
    WriteComplete
}

public enum UpdateJournalMode
{
    Applying,
    RollingBack
}

public sealed record UpdateOperation(
    int Ordinal,
    UpdateOperationKind Kind,
    string TargetRelativePath,
    bool Existed,
    long? OldLength,
    string? OldSha256,
    string? BackupRelativePath,
    string? BackupSha256,
    long NewLength,
    string NewSha256,
    UpdateOperationState State);

public sealed record UpdateOperationJournal(
    int SchemaVersion,
    long Generation,
    ProtectedTransactionId TransactionId,
    UpdateJournalMode Mode,
    int RollbackCursor,
    bool RollbackMutationStarted,
    IReadOnlyList<UpdateOperation> Operations);

public static class UpdateOperationJournalCodec
{
    public const int SchemaVersion = 1;
    public const int MaximumJournalBytes = 16 * 1024 * 1024;
    public const int MaximumJsonDepth = 64;
    public const int MaximumStringCharacters = 32_767;

    private const int JournalPropertyCount = 7;
    private const int OperationPropertyCount = 11;

    public static bool TrySerialize(
        UpdateOperationJournal? journal,
        out byte[] bytes)
    {
        bytes = [];
        if (!TrySnapshot(journal, out var snapshot)
            || !ValidateSnapshot(snapshot!))
        {
            return false;
        }

        return TryWrite(snapshot!, true, out bytes);
    }

    public static bool TryParse(
        ReadOnlySpan<byte> bytes,
        out UpdateOperationJournal? journal)
    {
        journal = null;
        if (bytes.IsEmpty || bytes.Length > MaximumJournalBytes)
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(
                bytes.ToArray(),
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = MaximumJsonDepth
                });

            if (!TryReadJournal(document.RootElement, out var parsed)
                || !TrySnapshot(parsed, out var snapshot)
                || !ValidateSnapshot(snapshot!)
                || !TryWrite(snapshot!, false, out _))
            {
                return false;
            }

            journal = snapshot;
            return true;
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            return false;
        }
    }

    public static bool IsValid(UpdateOperationJournal? journal)
    {
        try
        {
            return TrySnapshot(journal, out var snapshot)
                && ValidateSnapshot(snapshot!)
                && TryWrite(snapshot!, false, out _);
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            return false;
        }
    }

    public static bool IsLegalTransition(
        UpdateOperationJournal? current,
        UpdateOperationJournal? next)
    {
        try
        {
            if (!TryGetValidSnapshot(current, out var currentSnapshot)
                || !TryGetValidSnapshot(next, out var nextSnapshot)
                || currentSnapshot!.Generation == long.MaxValue
                || nextSnapshot!.Generation != currentSnapshot.Generation + 1
                || !HasSameImmutablePlan(currentSnapshot, nextSnapshot))
            {
                return false;
            }

            if (currentSnapshot.Mode == UpdateJournalMode.Applying)
            {
                return nextSnapshot.Mode switch
                {
                    UpdateJournalMode.Applying =>
                        IsSingleApplyingAdvance(currentSnapshot, nextSnapshot),
                    UpdateJournalMode.RollingBack =>
                        IsRollbackEntry(currentSnapshot, nextSnapshot),
                    _ => false
                };
            }

            return currentSnapshot.Mode == UpdateJournalMode.RollingBack
                && nextSnapshot.Mode == UpdateJournalMode.RollingBack
                && IsRollbackAdvance(currentSnapshot, nextSnapshot);
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            return false;
        }
    }

    public static bool IsInitialPlan(UpdateOperationJournal? journal)
    {
        try
        {
            if (!TryGetValidSnapshot(journal, out var snapshot)
                || snapshot!.Generation != 1
                || snapshot.Mode != UpdateJournalMode.Applying
                || snapshot.RollbackCursor != -1
                || snapshot.RollbackMutationStarted)
            {
                return false;
            }

            return snapshot.Operations.All(
                operation => operation.State == UpdateOperationState.Planned);
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            return false;
        }
    }

    public static bool TryParseCanonical(
        ReadOnlySpan<byte> bytes,
        out UpdateOperationJournal? journal)
    {
        journal = null;
        if (bytes.IsEmpty || bytes.Length > MaximumJournalBytes)
        {
            return false;
        }

        try
        {
            var input = bytes.ToArray();
            if (!TryParse(input, out var parsed)
                || !TrySerialize(parsed, out var canonical)
                || !input.AsSpan().SequenceEqual(canonical))
            {
                return false;
            }

            journal = parsed;
            return true;
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            return false;
        }
    }

    public static bool TryValidateCanonicalSuccessor(
        ReadOnlySpan<byte> nextJournalBytes,
        string? previousCanonicalSha256,
        out UpdateOperationJournal? nextJournal)
    {
        nextJournal = null;
        try
        {
            if (!TryParseCanonical(nextJournalBytes, out var parsed)
                || parsed is null)
            {
                return false;
            }

            if (parsed.Generation == 1)
            {
                if (previousCanonicalSha256 is not null
                    || !IsInitialPlan(parsed))
                {
                    return false;
                }

                nextJournal = parsed;
                return true;
            }

            if (parsed.Generation <= 1
                || !IsSha256(previousCanonicalSha256))
            {
                return false;
            }

            var expectedHash = Convert.FromHexString(
                previousCanonicalSha256!);
            foreach (var predecessor in ReconstructImmediatePredecessors(parsed))
            {
                if (predecessor.Generation == 1
                    && !IsInitialPlan(predecessor)
                    || !IsLegalTransition(predecessor, parsed)
                    || !TrySerialize(predecessor, out var predecessorBytes))
                {
                    continue;
                }

                var actualHash = SHA256.HashData(predecessorBytes);
                if (!CryptographicOperations.FixedTimeEquals(
                        actualHash,
                        expectedHash))
                {
                    continue;
                }

                nextJournal = parsed;
                return true;
            }

            return false;
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            nextJournal = null;
            return false;
        }
    }

    private static IReadOnlyList<UpdateOperationJournal>
        ReconstructImmediatePredecessors(UpdateOperationJournal next)
    {
        var predecessors = new List<UpdateOperationJournal>(3);
        var previousGeneration = next.Generation - 1;

        if (next.Mode == UpdateJournalMode.Applying)
        {
            if (TryReconstructApplyingPredecessor(
                    next,
                    previousGeneration,
                    out var applyingPredecessor))
            {
                predecessors.Add(applyingPredecessor!);
            }

            return predecessors;
        }

        predecessors.Add(next with
        {
            Generation = previousGeneration,
            Mode = UpdateJournalMode.Applying,
            RollbackCursor = -1,
            RollbackMutationStarted = false,
            Operations = CloneOperations(next.Operations)
        });

        if (next.RollbackMutationStarted)
        {
            predecessors.Add(next with
            {
                Generation = previousGeneration,
                RollbackMutationStarted = false,
                Operations = CloneOperations(next.Operations)
            });
            return predecessors;
        }

        var higherTouched = FindNextHigherTouched(
            next.Operations,
            next.RollbackCursor);
        if (higherTouched < 0)
        {
            return predecessors;
        }

        predecessors.Add(next with
        {
            Generation = previousGeneration,
            RollbackCursor = higherTouched,
            RollbackMutationStarted = false,
            Operations = CloneOperations(next.Operations)
        });
        predecessors.Add(next with
        {
            Generation = previousGeneration,
            RollbackCursor = higherTouched,
            RollbackMutationStarted = true,
            Operations = CloneOperations(next.Operations)
        });
        return predecessors;
    }

    private static bool TryReconstructApplyingPredecessor(
        UpdateOperationJournal next,
        long previousGeneration,
        out UpdateOperationJournal? predecessor)
    {
        predecessor = null;
        for (var index = 0; index < next.Operations.Count; index++)
        {
            var previousState = next.Operations[index].State switch
            {
                UpdateOperationState.BackupStarted =>
                    UpdateOperationState.Planned,
                UpdateOperationState.WriteStarted =>
                    UpdateOperationState.BackupComplete,
                _ => (UpdateOperationState?)null
            };
            if (previousState.HasValue)
            {
                predecessor = WithReconstructedState(
                    next,
                    previousGeneration,
                    index,
                    previousState.Value);
                return true;
            }
        }

        for (var index = next.Operations.Count - 1; index >= 0; index--)
        {
            if (next.Operations[index].State
                == UpdateOperationState.WriteComplete)
            {
                predecessor = WithReconstructedState(
                    next,
                    previousGeneration,
                    index,
                    UpdateOperationState.WriteStarted);
                return true;
            }
        }

        for (var index = next.Operations.Count - 1; index >= 0; index--)
        {
            if (next.Operations[index].State
                == UpdateOperationState.BackupComplete)
            {
                predecessor = WithReconstructedState(
                    next,
                    previousGeneration,
                    index,
                    UpdateOperationState.BackupStarted);
                return true;
            }
        }

        return false;
    }

    private static UpdateOperationJournal WithReconstructedState(
        UpdateOperationJournal next,
        long previousGeneration,
        int ordinal,
        UpdateOperationState state)
    {
        var operations = CloneOperations(next.Operations);
        operations[ordinal] = operations[ordinal] with { State = state };
        return next with
        {
            Generation = previousGeneration,
            Operations = operations
        };
    }

    private static UpdateOperation[] CloneOperations(
        IReadOnlyList<UpdateOperation> operations)
    {
        var clone = new UpdateOperation[operations.Count];
        for (var index = 0; index < operations.Count; index++)
        {
            clone[index] = operations[index] with { };
        }

        return clone;
    }

    private static int FindNextHigherTouched(
        IReadOnlyList<UpdateOperation> operations,
        int cursor)
    {
        for (var index = cursor + 1; index < operations.Count; index++)
        {
            if (IsTouched(operations[index].State))
            {
                return index;
            }
        }

        return -1;
    }
    private static bool TryGetValidSnapshot(
        UpdateOperationJournal? journal,
        out UpdateOperationJournal? snapshot)
    {
        snapshot = null;
        return TrySnapshot(journal, out snapshot)
            && ValidateSnapshot(snapshot!)
            && TryWrite(snapshot!, false, out _);
    }

    private static bool TrySnapshot(
        UpdateOperationJournal? journal,
        out UpdateOperationJournal? snapshot)
    {
        snapshot = null;
        if (journal?.Operations is null)
        {
            return false;
        }

        try
        {
            var count = journal.Operations.Count;
            if (count is < 1 or > WindowsReleasePathPolicy.MaximumArchiveEntries)
            {
                return false;
            }

            var operations = new UpdateOperation[count];
            for (var index = 0; index < count; index++)
            {
                var operation = journal.Operations[index];
                if (operation is null)
                {
                    return false;
                }

                operations[index] = operation with { };
            }

            if (journal.Operations.Count != count)
            {
                return false;
            }

            snapshot = journal with { Operations = operations };
            return true;
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            return false;
        }
    }

    private static bool ValidateSnapshot(UpdateOperationJournal journal)
    {
        if (journal.SchemaVersion != SchemaVersion
            || journal.Generation <= 0
            || !journal.TransactionId.IsValid
            || !Enum.IsDefined(journal.Mode)
            || journal.TransactionId.DirectoryName.Length != 32
            || !IsLowerHex(journal.TransactionId.DirectoryName, 32))
        {
            return false;
        }

        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var backups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var manifestCount = 0;

        for (var index = 0; index < journal.Operations.Count; index++)
        {
            var operation = journal.Operations[index];
            if (operation.Ordinal != index
                || !Enum.IsDefined(operation.Kind)
                || !Enum.IsDefined(operation.State)
                || !IsCanonicalSafePath(operation.TargetRelativePath)
                || !targets.Add(operation.TargetRelativePath)
                || operation.NewLength < 0
                || operation.NewLength
                    > UpdatePackageLimits.Default.MaximumFileBytes
                || !IsSha256(operation.NewSha256))
            {
                return false;
            }

            var targetsManifest = operation.TargetRelativePath.Equals(
                UpdateReleaseContract.ReleaseManifestPath,
                StringComparison.OrdinalIgnoreCase);

            switch (operation.Kind)
            {
                case UpdateOperationKind.Create:
                    if (targetsManifest
                        || operation.Existed
                        || operation.OldLength.HasValue
                        || operation.OldSha256 is not null
                        || operation.BackupRelativePath is not null
                        || operation.BackupSha256 is not null)
                    {
                        return false;
                    }

                    break;

                case UpdateOperationKind.Replace:
                    if (targetsManifest
                        || !ValidateReplacement(operation, backups))
                    {
                        return false;
                    }

                    break;

                case UpdateOperationKind.ReplaceManifest:
                    manifestCount++;
                    if (index != journal.Operations.Count - 1
                        || !operation.TargetRelativePath.Equals(
                            UpdateReleaseContract.ReleaseManifestPath,
                            StringComparison.Ordinal)
                        || !ValidateReplacement(operation, backups))
                    {
                        return false;
                    }

                    break;

                default:
                    return false;
            }
        }

        if (manifestCount != 1 || !HasValidCheckpointShape(journal.Operations))
        {
            return false;
        }

        return journal.Mode switch
        {
            UpdateJournalMode.Applying =>
                journal.RollbackCursor == -1
                && !journal.RollbackMutationStarted,
            UpdateJournalMode.RollingBack =>
                HasValidRollbackShape(journal),
            _ => false
        };
    }

    private static bool ValidateReplacement(
        UpdateOperation operation,
        HashSet<string> backups)
    {
        return operation.Existed
            && operation.OldLength.HasValue
            && operation.OldLength.Value >= 0
            && operation.OldLength.Value
                <= UpdatePackageLimits.Default.MaximumFileBytes
            && IsSha256(operation.OldSha256)
            && IsCanonicalSafePath(operation.BackupRelativePath)
            && operation.BackupRelativePath!.Equals(
                operation.TargetRelativePath,
                StringComparison.Ordinal)
            && backups.Add(operation.BackupRelativePath)
            && IsSha256(operation.BackupSha256)
            && operation.BackupSha256!.Equals(
                operation.OldSha256,
                StringComparison.Ordinal);
    }

    private static bool HasValidCheckpointShape(
        IReadOnlyList<UpdateOperation> operations) =>
        HasBackupCheckpointShape(operations)
        || HasWriteCheckpointShape(operations);

    private static bool HasBackupCheckpointShape(
        IReadOnlyList<UpdateOperation> operations)
    {
        var index = 0;
        while (index < operations.Count
               && operations[index].State == UpdateOperationState.BackupComplete)
        {
            index++;
        }

        if (index < operations.Count
            && operations[index].State == UpdateOperationState.BackupStarted)
        {
            index++;
        }

        while (index < operations.Count
               && operations[index].State == UpdateOperationState.Planned)
        {
            index++;
        }

        return index == operations.Count;
    }

    private static bool HasWriteCheckpointShape(
        IReadOnlyList<UpdateOperation> operations)
    {
        var index = 0;
        while (index < operations.Count
               && operations[index].State == UpdateOperationState.WriteComplete)
        {
            index++;
        }

        if (index < operations.Count
            && operations[index].State == UpdateOperationState.WriteStarted)
        {
            index++;
        }

        while (index < operations.Count
               && operations[index].State == UpdateOperationState.BackupComplete)
        {
            index++;
        }

        return index == operations.Count;
    }

    private static bool HasValidRollbackShape(UpdateOperationJournal journal)
    {
        if (journal.RollbackCursor < -1
            || journal.RollbackCursor >= journal.Operations.Count
            || (journal.RollbackCursor == -1
                && journal.RollbackMutationStarted))
        {
            return false;
        }

        return journal.RollbackCursor == -1
            || IsTouched(journal.Operations[journal.RollbackCursor].State);
    }

    private static bool HasSameImmutablePlan(
        UpdateOperationJournal current,
        UpdateOperationJournal next)
    {
        if (current.SchemaVersion != next.SchemaVersion
            || current.TransactionId != next.TransactionId
            || current.Operations.Count != next.Operations.Count)
        {
            return false;
        }

        for (var index = 0; index < current.Operations.Count; index++)
        {
            var left = current.Operations[index];
            var right = next.Operations[index];
            if (left.Ordinal != right.Ordinal
                || left.Kind != right.Kind
                || !string.Equals(
                    left.TargetRelativePath,
                    right.TargetRelativePath,
                    StringComparison.Ordinal)
                || left.Existed != right.Existed
                || left.OldLength != right.OldLength
                || !string.Equals(
                    left.OldSha256,
                    right.OldSha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    left.BackupRelativePath,
                    right.BackupRelativePath,
                    StringComparison.Ordinal)
                || !string.Equals(
                    left.BackupSha256,
                    right.BackupSha256,
                    StringComparison.Ordinal)
                || left.NewLength != right.NewLength
                || !string.Equals(
                    left.NewSha256,
                    right.NewSha256,
                    StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsSingleApplyingAdvance(
        UpdateOperationJournal current,
        UpdateOperationJournal next)
    {
        var changed = 0;
        for (var index = 0; index < current.Operations.Count; index++)
        {
            var currentState = current.Operations[index].State;
            var nextState = next.Operations[index].State;
            if (currentState == nextState)
            {
                continue;
            }

            changed++;
            if (changed > 1 || !IsNextCheckpoint(currentState, nextState))
            {
                return false;
            }
        }

        return changed == 1;
    }

    private static bool IsRollbackEntry(
        UpdateOperationJournal current,
        UpdateOperationJournal next) =>
        HaveSameStates(current.Operations, next.Operations)
        && next.RollbackCursor == FindHighestTouched(current.Operations)
        && !next.RollbackMutationStarted;

    private static bool IsRollbackAdvance(
        UpdateOperationJournal current,
        UpdateOperationJournal next)
    {
        if (!HaveSameStates(current.Operations, next.Operations)
            || current.RollbackCursor < 0)
        {
            return false;
        }

        var previousTouched = FindPreviousTouched(
            current.Operations,
            current.RollbackCursor);

        if (!current.RollbackMutationStarted)
        {
            return (next.RollbackCursor == current.RollbackCursor
                    && next.RollbackMutationStarted)
                || (next.RollbackCursor == previousTouched
                    && !next.RollbackMutationStarted);
        }

        return next.RollbackCursor == previousTouched
            && !next.RollbackMutationStarted;
    }

    private static bool HaveSameStates(
        IReadOnlyList<UpdateOperation> current,
        IReadOnlyList<UpdateOperation> next)
    {
        for (var index = 0; index < current.Count; index++)
        {
            if (current[index].State != next[index].State)
            {
                return false;
            }
        }

        return true;
    }

    private static int FindHighestTouched(
        IReadOnlyList<UpdateOperation> operations)
    {
        for (var index = operations.Count - 1; index >= 0; index--)
        {
            if (IsTouched(operations[index].State))
            {
                return index;
            }
        }

        return -1;
    }

    private static int FindPreviousTouched(
        IReadOnlyList<UpdateOperation> operations,
        int cursor)
    {
        for (var index = cursor - 1; index >= 0; index--)
        {
            if (IsTouched(operations[index].State))
            {
                return index;
            }
        }

        return -1;
    }

    private static bool IsTouched(UpdateOperationState state) =>
        state is UpdateOperationState.WriteStarted
            or UpdateOperationState.WriteComplete;

    private static bool IsNextCheckpoint(
        UpdateOperationState current,
        UpdateOperationState next) =>
        (current, next) switch
        {
            (UpdateOperationState.Planned,
                UpdateOperationState.BackupStarted) => true,
            (UpdateOperationState.BackupStarted,
                UpdateOperationState.BackupComplete) => true,
            (UpdateOperationState.BackupComplete,
                UpdateOperationState.WriteStarted) => true,
            (UpdateOperationState.WriteStarted,
                UpdateOperationState.WriteComplete) => true,
            _ => false
        };

    private static bool IsCanonicalSafePath(string? path)
    {
        if (path is null || path.Length > MaximumStringCharacters)
        {
            return false;
        }

        var result = WindowsReleasePathPolicy.Validate(path);
        return result.Success
            && string.Equals(
                result.CanonicalKey,
                path,
                StringComparison.Ordinal)
            && !ReleaseManagedPathPolicy.IsProtectedPayloadPath(path);
    }

    private static bool IsSha256(string? value) =>
        value is not null && IsLowerHex(value, 64);

    private static bool IsLowerHex(string value, int requiredLength)
    {
        if (value.Length != requiredLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f'))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryReadJournal(
        JsonElement element,
        out UpdateOperationJournal? journal)
    {
        journal = null;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var schemaVersion = 0;
        long generation = 0;
        var transactionId = default(ProtectedTransactionId);
        var mode = default(UpdateJournalMode);
        var rollbackCursor = 0;
        var rollbackMutationStarted = false;
        IReadOnlyList<UpdateOperation>? operations = null;

        foreach (var property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                return false;
            }

            switch (property.Name)
            {
                case "schemaVersion":
                    if (!property.Value.TryGetInt32(out schemaVersion))
                    {
                        return false;
                    }

                    break;
                case "generation":
                    if (!property.Value.TryGetInt64(out generation))
                    {
                        return false;
                    }

                    break;
                case "transactionId":
                    if (!TryReadTransactionId(
                        property.Value,
                        out transactionId))
                    {
                        return false;
                    }

                    break;
                case "mode":
                    if (!TryReadMode(property.Value, out mode))
                    {
                        return false;
                    }

                    break;
                case "rollbackCursor":
                    if (!property.Value.TryGetInt32(out rollbackCursor))
                    {
                        return false;
                    }

                    break;
                case "rollbackMutationStarted":
                    if (property.Value.ValueKind
                        is not JsonValueKind.True
                        and not JsonValueKind.False)
                    {
                        return false;
                    }

                    rollbackMutationStarted = property.Value.GetBoolean();
                    break;
                case "operations":
                    if (!TryReadOperations(property.Value, out operations))
                    {
                        return false;
                    }

                    break;
                default:
                    return false;
            }
        }

        if (seen.Count != JournalPropertyCount || operations is null)
        {
            return false;
        }

        journal = new UpdateOperationJournal(
            schemaVersion,
            generation,
            transactionId,
            mode,
            rollbackCursor,
            rollbackMutationStarted,
            operations);
        return true;
    }

    private static bool TryReadOperations(
        JsonElement element,
        out IReadOnlyList<UpdateOperation>? operations)
    {
        operations = null;
        if (element.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        var count = element.GetArrayLength();
        if (count is < 1 or > WindowsReleasePathPolicy.MaximumArchiveEntries)
        {
            return false;
        }

        var parsed = new UpdateOperation[count];
        var index = 0;
        foreach (var item in element.EnumerateArray())
        {
            if (!TryReadOperation(item, out var operation))
            {
                return false;
            }

            parsed[index++] = operation!;
        }

        operations = parsed;
        return true;
    }

    private static bool TryReadOperation(
        JsonElement element,
        out UpdateOperation? operation)
    {
        operation = null;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordinal = 0;
        var kind = default(UpdateOperationKind);
        string? targetRelativePath = null;
        var existed = false;
        long? oldLength = null;
        string? oldSha256 = null;
        string? backupRelativePath = null;
        string? backupSha256 = null;
        long newLength = 0;
        string? newSha256 = null;
        var state = default(UpdateOperationState);

        foreach (var property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name))
            {
                return false;
            }

            switch (property.Name)
            {
                case "ordinal":
                    if (!property.Value.TryGetInt32(out ordinal))
                    {
                        return false;
                    }

                    break;
                case "kind":
                    if (!TryReadKind(property.Value, out kind))
                    {
                        return false;
                    }

                    break;
                case "targetRelativePath":
                    if (!TryReadRequiredString(
                        property.Value,
                        out targetRelativePath))
                    {
                        return false;
                    }

                    break;
                case "existed":
                    if (property.Value.ValueKind
                        is not JsonValueKind.True
                        and not JsonValueKind.False)
                    {
                        return false;
                    }

                    existed = property.Value.GetBoolean();
                    break;
                case "oldLength":
                    if (!TryReadNullableInt64(property.Value, out oldLength))
                    {
                        return false;
                    }

                    break;
                case "oldSha256":
                    if (!TryReadNullableString(
                        property.Value,
                        out oldSha256))
                    {
                        return false;
                    }

                    break;
                case "backupRelativePath":
                    if (!TryReadNullableString(
                        property.Value,
                        out backupRelativePath))
                    {
                        return false;
                    }

                    break;
                case "backupSha256":
                    if (!TryReadNullableString(
                        property.Value,
                        out backupSha256))
                    {
                        return false;
                    }

                    break;
                case "newLength":
                    if (!property.Value.TryGetInt64(out newLength))
                    {
                        return false;
                    }

                    break;
                case "newSha256":
                    if (!TryReadRequiredString(
                        property.Value,
                        out newSha256))
                    {
                        return false;
                    }

                    break;
                case "state":
                    if (!TryReadState(property.Value, out state))
                    {
                        return false;
                    }

                    break;
                default:
                    return false;
            }
        }

        if (seen.Count != OperationPropertyCount
            || targetRelativePath is null
            || newSha256 is null)
        {
            return false;
        }

        operation = new UpdateOperation(
            ordinal,
            kind,
            targetRelativePath,
            existed,
            oldLength,
            oldSha256,
            backupRelativePath,
            backupSha256,
            newLength,
            newSha256,
            state);
        return true;
    }

    private static bool TryReadTransactionId(
        JsonElement element,
        out ProtectedTransactionId transactionId)
    {
        transactionId = default;
        if (!TryReadRequiredString(element, out var value)
            || !IsLowerHex(value!, 32)
            || !Guid.TryParseExact(value, "N", out var guid)
            || guid == Guid.Empty)
        {
            return false;
        }

        transactionId = new ProtectedTransactionId(guid);
        return true;
    }

    private static bool TryReadMode(
        JsonElement element,
        out UpdateJournalMode mode)
    {
        mode = default;
        if (!TryReadRequiredString(element, out var value))
        {
            return false;
        }

        return value switch
        {
            "Applying" => Assign(UpdateJournalMode.Applying, out mode),
            "RollingBack" => Assign(UpdateJournalMode.RollingBack, out mode),
            _ => false
        };
    }

    private static bool TryReadKind(
        JsonElement element,
        out UpdateOperationKind kind)
    {
        kind = default;
        if (!TryReadRequiredString(element, out var value))
        {
            return false;
        }

        return value switch
        {
            "Create" => Assign(UpdateOperationKind.Create, out kind),
            "Replace" => Assign(UpdateOperationKind.Replace, out kind),
            "ReplaceManifest" =>
                Assign(UpdateOperationKind.ReplaceManifest, out kind),
            _ => false
        };
    }

    private static bool TryReadState(
        JsonElement element,
        out UpdateOperationState state)
    {
        state = default;
        if (!TryReadRequiredString(element, out var value))
        {
            return false;
        }

        return value switch
        {
            "Planned" => Assign(UpdateOperationState.Planned, out state),
            "BackupStarted" =>
                Assign(UpdateOperationState.BackupStarted, out state),
            "BackupComplete" =>
                Assign(UpdateOperationState.BackupComplete, out state),
            "WriteStarted" =>
                Assign(UpdateOperationState.WriteStarted, out state),
            "WriteComplete" =>
                Assign(UpdateOperationState.WriteComplete, out state),
            _ => false
        };
    }

    private static bool Assign<T>(T value, out T destination)
    {
        destination = value;
        return true;
    }

    private static bool TryReadRequiredString(
        JsonElement element,
        out string? value)
    {
        value = null;
        if (element.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = element.GetString();
        return value is not null
            && value.Length <= MaximumStringCharacters;
    }

    private static bool TryReadNullableString(
        JsonElement element,
        out string? value)
    {
        value = null;
        if (element.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        return TryReadRequiredString(element, out value);
    }

    private static bool TryReadNullableInt64(
        JsonElement element,
        out long? value)
    {
        value = null;
        if (element.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (!element.TryGetInt64(out var parsed))
        {
            return false;
        }

        value = parsed;
        return true;
    }

    private static bool TryWrite(
        UpdateOperationJournal journal,
        bool capture,
        out byte[] bytes)
    {
        bytes = [];
        try
        {
            using var stream = new BoundedWriteStream(capture);
            using (var writer = new Utf8JsonWriter(
                       stream,
                       new JsonWriterOptions
                       {
                           Indented = false,
                           SkipValidation = false
                       }))
            {
                writer.WriteStartObject();
                writer.WriteNumber("schemaVersion", journal.SchemaVersion);
                writer.WriteNumber("generation", journal.Generation);
                writer.WriteString(
                    "transactionId",
                    journal.TransactionId.DirectoryName);
                writer.WriteString("mode", WriteMode(journal.Mode));
                writer.WriteNumber("rollbackCursor", journal.RollbackCursor);
                writer.WriteBoolean(
                    "rollbackMutationStarted",
                    journal.RollbackMutationStarted);
                writer.WritePropertyName("operations");
                writer.WriteStartArray();

                foreach (var operation in journal.Operations)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("ordinal", operation.Ordinal);
                    writer.WriteString("kind", WriteKind(operation.Kind));
                    writer.WriteString(
                        "targetRelativePath",
                        operation.TargetRelativePath);
                    writer.WriteBoolean("existed", operation.Existed);
                    WriteNullableNumber(
                        writer,
                        "oldLength",
                        operation.OldLength);
                    WriteNullableString(
                        writer,
                        "oldSha256",
                        operation.OldSha256);
                    WriteNullableString(
                        writer,
                        "backupRelativePath",
                        operation.BackupRelativePath);
                    WriteNullableString(
                        writer,
                        "backupSha256",
                        operation.BackupSha256);
                    writer.WriteNumber("newLength", operation.NewLength);
                    writer.WriteString("newSha256", operation.NewSha256);
                    writer.WriteString("state", WriteState(operation.State));
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.Flush();
            }

            bytes = stream.ToArray();
            return true;
        }
        catch (Exception exception) when (IsCatchable(exception))
        {
            bytes = [];
            return false;
        }
    }

    private static void WriteNullableNumber(
        Utf8JsonWriter writer,
        string propertyName,
        long? value)
    {
        writer.WritePropertyName(propertyName);
        if (value.HasValue)
        {
            writer.WriteNumberValue(value.Value);
        }
        else
        {
            writer.WriteNullValue();
        }
    }

    private static void WriteNullableString(
        Utf8JsonWriter writer,
        string propertyName,
        string? value)
    {
        writer.WritePropertyName(propertyName);
        if (value is null)
        {
            writer.WriteNullValue();
        }
        else
        {
            writer.WriteStringValue(value);
        }
    }

    private static string WriteMode(UpdateJournalMode mode) =>
        mode switch
        {
            UpdateJournalMode.Applying => "Applying",
            UpdateJournalMode.RollingBack => "RollingBack",
            _ => throw new InvalidOperationException("Unknown journal mode.")
        };

    private static string WriteKind(UpdateOperationKind kind) =>
        kind switch
        {
            UpdateOperationKind.Create => "Create",
            UpdateOperationKind.Replace => "Replace",
            UpdateOperationKind.ReplaceManifest => "ReplaceManifest",
            _ => throw new InvalidOperationException("Unknown operation kind.")
        };

    private static string WriteState(UpdateOperationState state) =>
        state switch
        {
            UpdateOperationState.Planned => "Planned",
            UpdateOperationState.BackupStarted => "BackupStarted",
            UpdateOperationState.BackupComplete => "BackupComplete",
            UpdateOperationState.WriteStarted => "WriteStarted",
            UpdateOperationState.WriteComplete => "WriteComplete",
            _ => throw new InvalidOperationException(
                "Unknown operation state.")
        };

    private static bool IsCatchable(Exception exception) =>
        exception is not OutOfMemoryException
            and not StackOverflowException
            and not AccessViolationException;

    private sealed class BoundedWriteStream(bool capture) : Stream
    {
        private readonly MemoryStream? _capture =
            capture ? new MemoryStream() : null;
        private long _length;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _length;

        public override long Position
        {
            get => _length;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            ArgumentOutOfRangeException.ThrowIfNegative(offset);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            if (buffer.Length - offset < count)
            {
                throw new ArgumentException(
                    "The offset and count exceed the buffer.");
            }

            Write(buffer.AsSpan(offset, count));
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length > MaximumJournalBytes - _length)
            {
                throw new InvalidDataException(
                    "The journal exceeds its byte limit.");
            }

            _capture?.Write(buffer);
            _length += buffer.Length;
        }

        public byte[] ToArray() => _capture?.ToArray() ?? [];

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) =>
            throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _capture?.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
