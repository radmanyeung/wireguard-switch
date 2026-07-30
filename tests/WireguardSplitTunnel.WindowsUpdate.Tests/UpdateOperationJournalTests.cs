using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class UpdateOperationJournalTests
{
    private static readonly ProtectedTransactionId TransactionId =
        new(Guid.Parse("00112233-4455-6677-8899-AABBCCDDEEFF"));

    [Fact]
    public void SerializeAndParse_UseOneDeterministicStrictRepresentation()
    {
        var journal = ValidJournal();

        UpdateOperationJournalCodec.TrySerialize(journal, out var first).Should().BeTrue();
        UpdateOperationJournalCodec.TrySerialize(journal, out var second).Should().BeTrue();

        first.Should().Equal(second);
        Encoding.UTF8.GetString(first).Should().Be(
            """{"schemaVersion":1,"generation":7,"transactionId":"00112233445566778899aabbccddeeff","mode":"Applying","rollbackCursor":-1,"rollbackMutationStarted":false,"operations":[{"ordinal":0,"kind":"Replace","targetRelativePath":"WireguardSplitTunnel/WireguardSplitTunnel.App.exe","existed":true,"oldLength":10,"oldSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","backupRelativePath":"WireguardSplitTunnel/WireguardSplitTunnel.App.exe","backupSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","newLength":11,"newSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"Planned"},{"ordinal":1,"kind":"Create","targetRelativePath":"assets/new.bin","existed":false,"oldLength":null,"oldSha256":null,"backupRelativePath":null,"backupSha256":null,"newLength":12,"newSha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","state":"Planned"},{"ordinal":2,"kind":"ReplaceManifest","targetRelativePath":"release-manifest.json","existed":true,"oldLength":13,"oldSha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","backupRelativePath":"release-manifest.json","backupSha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","newLength":14,"newSha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","state":"Planned"}]}""");

        UpdateOperationJournalCodec.TryParse(first, out var parsed).Should().BeTrue();
        parsed.Should().BeEquivalentTo(journal);
    }

    [Fact]
    public void Parse_RejectsMalformedOrSchemaDeviatingJson()
    {
        var valid = Serialize(ValidJournal());
        var invalid = new[]
        {
            valid.Replace("\"operations\":", "\"unknown\":0,\"operations\":", StringComparison.Ordinal),
            valid.Replace("\"schemaVersion\":1,", string.Empty, StringComparison.Ordinal),
            valid.Replace("\"generation\":7,", "\"generation\":7,\"generation\":7,", StringComparison.Ordinal),
            valid.Replace("\"generation\":7,", "\"Generation\":7,", StringComparison.Ordinal),
            valid.Replace("\"ordinal\":0,", "\"unknown\":0,\"ordinal\":0,", StringComparison.Ordinal),
            valid.Replace("\"ordinal\":0,", "\"ordinal\":0,\"ordinal\":0,", StringComparison.Ordinal),
            valid.Replace("{\"schemaVersion\"", "{/*comment*/\"schemaVersion\"", StringComparison.Ordinal),
            valid.Replace("\"operations\":[", "\"operations\":[,", StringComparison.Ordinal),
            valid + "{}",
            valid.Replace("\"Applying\"", "\"applying\"", StringComparison.Ordinal),
            valid.Replace("\"schemaVersion\":1", "\"schemaVersion\":2", StringComparison.Ordinal),
            valid.Replace("\"generation\":7", "\"generation\":0", StringComparison.Ordinal),
            valid.Replace(
                "\"00112233445566778899aabbccddeeff\"",
                "\"00112233-4455-6677-8899-aabbccddeeff\"",
                StringComparison.Ordinal)
        };

        foreach (var json in invalid)
        {
            UpdateOperationJournalCodec.TryParse(
                    Encoding.UTF8.GetBytes(json),
                    out var journal)
                .Should()
                .BeFalse(json);
            journal.Should().BeNull();
        }
    }

    [Fact]
    public void Parse_AllowsWhitespaceAndPropertyReorderingWithinTheStrictSchema()
    {
        var json = Serialize(ValidJournal()).Replace(
            "{\"schemaVersion\":1,\"generation\":7,",
            "{\n  \"generation\": 7,\n  \"schemaVersion\": 1,",
            StringComparison.Ordinal);

        UpdateOperationJournalCodec.TryParse(
                Encoding.UTF8.GetBytes(json),
                out var parsed)
            .Should()
            .BeTrue();
        parsed.Should().BeEquivalentTo(ValidJournal());
    }

    [Theory]
    [MemberData(nameof(InvalidJournals))]
    public void Validate_RejectsInvalidSemanticShapes(UpdateOperationJournal journal)
    {
        UpdateOperationJournalCodec.IsValid(journal).Should().BeFalse();
        UpdateOperationJournalCodec.TrySerialize(journal, out var bytes).Should().BeFalse();
        bytes.Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(ValidStateShapes))]
    public void Validate_AcceptsOnlyACompletedPrefixAndAtMostOneActiveOperation(
        UpdateOperationState[] states)
    {
        UpdateOperationJournalCodec.IsValid(ValidJournal(states)).Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(InvalidStateShapes))]
    public void Validate_RejectsInvalidCheckpointShapes(UpdateOperationState[] states)
    {
        UpdateOperationJournalCodec.IsValid(ValidJournal(states)).Should().BeFalse();
    }

    [Fact]
    public void Validate_EnforcesModeSpecificRollbackShape()
    {
        var applying = ValidJournal(
            UpdateOperationState.WriteComplete,
            UpdateOperationState.WriteStarted,
            UpdateOperationState.BackupComplete);

        UpdateOperationJournalCodec.IsValid(
            applying with { RollbackCursor = 1 }).Should().BeFalse();
        UpdateOperationJournalCodec.IsValid(
            applying with { RollbackMutationStarted = true }).Should().BeFalse();

        var rollingBack = applying with
        {
            Generation = 8,
            Mode = UpdateJournalMode.RollingBack,
            RollbackCursor = 1
        };
        UpdateOperationJournalCodec.IsValid(rollingBack).Should().BeTrue();
        UpdateOperationJournalCodec.IsValid(
            rollingBack with { RollbackCursor = 2 }).Should().BeFalse();
        UpdateOperationJournalCodec.IsValid(
            rollingBack with { RollbackCursor = -1, RollbackMutationStarted = true })
            .Should()
            .BeFalse();
        UpdateOperationJournalCodec.IsValid(
            rollingBack with { RollbackCursor = 3 }).Should().BeFalse();
    }

    [Fact]
    public void TransitionValidator_AllowsOneApplyingCheckpointAtATime()
    {
        var planned = ValidJournal();
        var backupStarted = Advance(planned, 0, UpdateOperationState.BackupStarted);

        UpdateOperationJournalCodec.IsLegalTransition(planned, backupStarted).Should().BeTrue();
        UpdateOperationJournalCodec.IsLegalTransition(
            planned,
            Advance(planned, 0, UpdateOperationState.BackupComplete)).Should().BeFalse();
        UpdateOperationJournalCodec.IsLegalTransition(
            planned,
            Advance(
                Advance(planned, 0, UpdateOperationState.BackupStarted),
                1,
                UpdateOperationState.BackupStarted)).Should().BeFalse();
        UpdateOperationJournalCodec.IsLegalTransition(
            planned,
            backupStarted with { Generation = planned.Generation }).Should().BeFalse();
        UpdateOperationJournalCodec.IsLegalTransition(
            planned,
            backupStarted with
            {
                Operations = backupStarted.Operations
                    .Select(
                        operation => operation.Ordinal == 0
                            ? operation with { NewLength = operation.NewLength + 1 }
                            : operation)
                    .ToArray()
            }).Should().BeFalse();

        var allBackedUp = ValidJournal(
            UpdateOperationState.BackupComplete,
            UpdateOperationState.BackupComplete,
            UpdateOperationState.BackupComplete);
        UpdateOperationJournalCodec.IsLegalTransition(
            allBackedUp,
            Advance(allBackedUp, 0, UpdateOperationState.WriteStarted)).Should().BeTrue();
        UpdateOperationJournalCodec.IsLegalTransition(
            allBackedUp,
            Advance(allBackedUp, 1, UpdateOperationState.WriteStarted)).Should().BeFalse();
    }

    [Fact]
    public void TransitionValidator_EntersRollbackAtHighestTouchedOperation()
    {
        var applying = ValidJournal(
            UpdateOperationState.WriteComplete,
            UpdateOperationState.WriteStarted,
            UpdateOperationState.BackupComplete);
        var rollingBack = applying with
        {
            Generation = applying.Generation + 1,
            Mode = UpdateJournalMode.RollingBack,
            RollbackCursor = 1
        };

        UpdateOperationJournalCodec.IsLegalTransition(applying, rollingBack).Should().BeTrue();
        UpdateOperationJournalCodec.IsLegalTransition(
            applying,
            rollingBack with { RollbackCursor = 0 }).Should().BeFalse();
        UpdateOperationJournalCodec.IsLegalTransition(
            applying,
            rollingBack with { RollbackMutationStarted = true }).Should().BeFalse();
        UpdateOperationJournalCodec.IsLegalTransition(
            applying,
            rollingBack with
            {
                Operations = rollingBack.Operations
                    .Select(
                        operation => operation.Ordinal == 1
                            ? operation with { State = UpdateOperationState.WriteComplete }
                            : operation)
                    .ToArray()
            }).Should().BeFalse();
    }

    [Fact]
    public void TransitionValidator_AllowsOnlyRollbackPreAndPostMutationCheckpoints()
    {
        var applying = ValidJournal(
            UpdateOperationState.WriteComplete,
            UpdateOperationState.WriteStarted,
            UpdateOperationState.BackupComplete);
        var rollingBack = applying with
        {
            Generation = applying.Generation + 1,
            Mode = UpdateJournalMode.RollingBack,
            RollbackCursor = 1
        };
        var beforeMutation = rollingBack with
        {
            Generation = rollingBack.Generation + 1,
            RollbackMutationStarted = true
        };
        var afterMutation = beforeMutation with
        {
            Generation = beforeMutation.Generation + 1,
            RollbackCursor = 0,
            RollbackMutationStarted = false
        };
        var idempotentSkip = rollingBack with
        {
            Generation = rollingBack.Generation + 1,
            RollbackCursor = 0
        };

        UpdateOperationJournalCodec.IsLegalTransition(
            rollingBack,
            beforeMutation).Should().BeTrue();
        UpdateOperationJournalCodec.IsLegalTransition(
            beforeMutation,
            afterMutation).Should().BeTrue();
        UpdateOperationJournalCodec.IsLegalTransition(
            rollingBack,
            idempotentSkip).Should().BeTrue();
        UpdateOperationJournalCodec.IsLegalTransition(
            rollingBack,
            rollingBack with
            {
                Generation = rollingBack.Generation + 1,
                RollbackCursor = -1
            }).Should().BeFalse();
        UpdateOperationJournalCodec.IsLegalTransition(
            beforeMutation,
            afterMutation with { RollbackMutationStarted = true }).Should().BeFalse();
        UpdateOperationJournalCodec.IsLegalTransition(
            beforeMutation,
            afterMutation with { Mode = UpdateJournalMode.Applying }).Should().BeFalse();
    }

    [Fact]
    public void InitialPlan_RequiresTheCanonicalGenerationOneStartingCheckpoint()
    {
        var initial = ValidJournal() with { Generation = 1 };

        UpdateOperationJournalCodec.IsInitialPlan(initial).Should().BeTrue();
        UpdateOperationJournalCodec.IsInitialPlan(
            initial with { Generation = 2 }).Should().BeFalse();
        UpdateOperationJournalCodec.IsInitialPlan(
            Advance(initial, 0, UpdateOperationState.BackupStarted) with
            {
                Generation = 1
            }).Should().BeFalse();
        UpdateOperationJournalCodec.IsInitialPlan(
            initial with
            {
                Mode = UpdateJournalMode.RollingBack,
                RollbackCursor = -1
            }).Should().BeFalse();
    }

    [Fact]
    public void CanonicalParser_RejectsEquivalentButNonCanonicalBytes()
    {
        var journal = ValidJournal();
        var canonical = SerializeBytes(journal);
        var reordered = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(canonical).Replace(
                "{\"schemaVersion\":1,\"generation\":7,",
                "{\n\"generation\":7,\"schemaVersion\":1,",
                StringComparison.Ordinal));

        UpdateOperationJournalCodec.TryParseCanonical(
                canonical,
                out var parsed)
            .Should()
            .BeTrue();
        parsed.Should().BeEquivalentTo(journal);
        UpdateOperationJournalCodec.TryParse(reordered, out _).Should().BeTrue();
        UpdateOperationJournalCodec.TryParseCanonical(
                reordered,
                out var nonCanonical)
            .Should()
            .BeFalse();
        nonCanonical.Should().BeNull();
    }

    [Fact]
    public void CanonicalSuccessor_AcceptsInitialAndEveryApplyingCheckpointClass()
    {
        var initial = ValidJournal() with { Generation = 1 };
        AssertCanonicalSuccessor(null, initial, previousSha256: null);
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(initial),
                CanonicalHash(initial),
                out _)
            .Should()
            .BeFalse();

        var backupStarted = Advance(
            initial,
            0,
            UpdateOperationState.BackupStarted);
        AssertCanonicalSuccessor(initial, backupStarted);

        var backupComplete = Advance(
            backupStarted,
            0,
            UpdateOperationState.BackupComplete);
        AssertCanonicalSuccessor(backupStarted, backupComplete);

        var allBackedUp = ValidJournal(
            UpdateOperationState.BackupComplete,
            UpdateOperationState.BackupComplete,
            UpdateOperationState.BackupComplete) with
        {
            Generation = 10
        };
        var writeStarted = Advance(
            allBackedUp,
            0,
            UpdateOperationState.WriteStarted);
        AssertCanonicalSuccessor(allBackedUp, writeStarted);

        var writeComplete = Advance(
            writeStarted,
            0,
            UpdateOperationState.WriteComplete);
        AssertCanonicalSuccessor(writeStarted, writeComplete);
    }

    [Fact]
    public void CanonicalSuccessor_ReconstructsRollbackEntryAndMutationCheckpoints()
    {
        var applying = ValidJournal(
            UpdateOperationState.WriteComplete,
            UpdateOperationState.WriteStarted,
            UpdateOperationState.BackupComplete);
        var rollbackEntry = applying with
        {
            Generation = applying.Generation + 1,
            Mode = UpdateJournalMode.RollingBack,
            RollbackCursor = 1
        };
        var mutationStarted = rollbackEntry with
        {
            Generation = rollbackEntry.Generation + 1,
            RollbackMutationStarted = true
        };

        AssertCanonicalSuccessor(applying, rollbackEntry);
        AssertCanonicalSuccessor(rollbackEntry, mutationStarted);
    }

    [Fact]
    public void CanonicalSuccessor_DisambiguatesBothRollbackCursorPredecessorsByHash()
    {
        var applying = ValidJournal(
            UpdateOperationState.WriteComplete,
            UpdateOperationState.WriteStarted,
            UpdateOperationState.BackupComplete);
        var rollbackEntry = applying with
        {
            Generation = applying.Generation + 1,
            Mode = UpdateJournalMode.RollingBack,
            RollbackCursor = 1
        };
        var afterMutation = rollbackEntry with
        {
            Generation = rollbackEntry.Generation + 1,
            RollbackCursor = 0
        };
        var mutatingPredecessor = rollbackEntry with
        {
            RollbackMutationStarted = true
        };

        AssertCanonicalSuccessor(rollbackEntry, afterMutation);
        AssertCanonicalSuccessor(mutatingPredecessor, afterMutation);
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(afterMutation),
                CanonicalHash(applying),
                out _)
            .Should()
            .BeFalse();
    }

    [Fact]
    public void CanonicalSuccessor_RejectsWrongHashPlanGenerationSkipAndRollbackCursor()
    {
        var previous = ValidJournal();
        var legal = Advance(
            previous,
            0,
            UpdateOperationState.BackupStarted);

        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(legal),
                Hash('f'),
                out _)
            .Should()
            .BeFalse();
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(legal),
                new string('A', 64),
                out _)
            .Should()
            .BeFalse();
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(legal),
                previousCanonicalSha256: null,
                out _)
            .Should()
            .BeFalse();

        var changedPlan = WithOperation(
            previous,
            0,
            operation => operation with
            {
                NewLength = operation.NewLength + 1
            });
        var changedPlanNext = Advance(
            changedPlan,
            0,
            UpdateOperationState.BackupStarted);
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(changedPlanNext),
                CanonicalHash(previous),
                out _)
            .Should()
            .BeFalse();

        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(legal with
                {
                    Generation = legal.Generation + 1
                }),
                CanonicalHash(previous),
                out _)
            .Should()
            .BeFalse();

        var skipped = Advance(
            previous,
            0,
            UpdateOperationState.BackupComplete);
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(skipped),
                CanonicalHash(previous),
                out _)
            .Should()
            .BeFalse();

        var applying = ValidJournal(
            UpdateOperationState.WriteComplete,
            UpdateOperationState.WriteStarted,
            UpdateOperationState.BackupComplete);
        var wrongCursor = applying with
        {
            Generation = applying.Generation + 1,
            Mode = UpdateJournalMode.RollingBack,
            RollbackCursor = 0
        };
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(wrongCursor),
                CanonicalHash(applying),
                out _)
            .Should()
            .BeFalse();

        var nonInitialGenerationOne = ValidJournal(
            UpdateOperationState.BackupStarted,
            UpdateOperationState.Planned,
            UpdateOperationState.Planned) with
        {
            Generation = 1
        };
        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(nonInitialGenerationOne),
                previousCanonicalSha256: null,
                out _)
            .Should()
            .BeFalse();
    }
    [Fact]
    public void Parse_RejectsBoundViolationsWithoutThrowing()
    {
        var oversized = new byte[UpdateOperationJournalCodec.MaximumJournalBytes + 1];
        oversized.AsSpan().Fill((byte)' ');

        var action = () => UpdateOperationJournalCodec.TryParse(oversized, out _);

        action.Should().NotThrow();
        UpdateOperationJournalCodec.TryParse(oversized, out _).Should().BeFalse();

        var deeplyNested = Encoding.UTF8.GetBytes(
            new string('[', UpdateOperationJournalCodec.MaximumJsonDepth + 1)
            + new string(']', UpdateOperationJournalCodec.MaximumJsonDepth + 1));
        UpdateOperationJournalCodec.TryParse(deeplyNested, out _).Should().BeFalse();
    }

    public static IEnumerable<object[]> ValidStateShapes()
    {
        yield return [States("PPP")];
        yield return [States("XSP")];
        yield return [States("XXX")];
        yield return [States("WIX")];
        yield return [States("WWW")];
    }

    public static IEnumerable<object[]> InvalidStateShapes()
    {
        yield return [States("SSP")];
        yield return [States("IIP")];
        yield return [States("IPP")];
        yield return [States("PXP")];
        yield return [States("XWP")];
        yield return [States("XIW")];
    }

    public static IEnumerable<object[]> InvalidJournals()
    {
        var valid = ValidJournal();
        yield return [valid with { SchemaVersion = 2 }];
        yield return [valid with { Generation = 0 }];
        yield return [valid with { TransactionId = new ProtectedTransactionId(Guid.Empty) }];
        yield return [valid with { Mode = (UpdateJournalMode)999 }];
        yield return
        [
            valid with
            {
                Operations = Enumerable.Repeat(
                        valid.Operations[0],
                        WindowsReleasePathPolicy.MaximumArchiveEntries + 1)
                    .ToArray()
            }
        ];
        yield return
        [
            WithOperation(
                valid,
                1,
                operation => operation with
                {
                    TargetRelativePath = new string(
                        'a',
                        UpdateOperationJournalCodec.MaximumStringCharacters + 1)
                })
        ];
        yield return [valid with { Operations = [] }];
        yield return [valid with { Operations = valid.Operations.Take(2).ToArray() }];
        yield return
        [
            WithOperation(valid, 0, operation => operation with { Ordinal = 1 })
        ];
        yield return
        [
            WithOperation(valid, 0, operation => operation with { NewSha256 = Hash('A') })
        ];
        yield return
        [
            WithOperation(valid, 0, operation => operation with { NewLength = -1 })
        ];
        yield return
        [
            WithOperation(
                valid,
                0,
                operation => operation with
                {
                    NewLength = UpdatePackageLimits.Default.MaximumFileBytes + 1
                })
        ];
        yield return
        [
            WithOperation(
                valid,
                0,
                operation => operation with { TargetRelativePath = "../escape" })
        ];
        yield return
        [
            WithOperation(
                valid,
                0,
                operation => operation with { TargetRelativePath = "state.json" })
        ];
        yield return
        [
            WithOperation(
                valid,
                1,
                operation => operation with
                {
                    TargetRelativePath =
                        UpdateReleaseContract.WindowsApplicationPath.ToUpperInvariant()
                })
        ];
        yield return
        [
            WithOperation(
                valid,
                0,
                operation => operation with { BackupRelativePath = "other.bin" })
        ];
        yield return
        [
            WithOperation(
                valid,
                1,
                operation => operation with
                {
                    Existed = true,
                    OldLength = 1,
                    OldSha256 = Hash('a'),
                    BackupRelativePath = "assets/new.bin",
                    BackupSha256 = Hash('a')
                })
        ];
        yield return
        [
            WithOperation(
                valid,
                0,
                operation => operation with { Existed = false })
        ];
        yield return
        [
            WithOperation(
                valid,
                0,
                operation => operation with { BackupSha256 = Hash('f') })
        ];
        yield return
        [
            valid with
            {
                Operations = valid.Operations
                    .Select(
                        operation => operation.Kind == UpdateOperationKind.ReplaceManifest
                            ? operation with { Kind = UpdateOperationKind.Replace }
                            : operation)
                    .ToArray()
            }
        ];
        yield return
        [
            valid with
            {
                Operations =
                [
                    valid.Operations[2] with { Ordinal = 0 },
                    valid.Operations[1],
                    valid.Operations[0] with { Ordinal = 2 }
                ]
            }
        ];
        yield return
        [
            WithOperation(
                valid,
                2,
                operation => operation with { TargetRelativePath = "other-manifest.json" })
        ];
    }

    private static UpdateOperationJournal ValidJournal(
        params UpdateOperationState[] states)
    {
        if (states.Length == 0)
        {
            states =
            [
                UpdateOperationState.Planned,
                UpdateOperationState.Planned,
                UpdateOperationState.Planned
            ];
        }

        return new UpdateOperationJournal(
            UpdateOperationJournalCodec.SchemaVersion,
            7,
            TransactionId,
            UpdateJournalMode.Applying,
            -1,
            false,
            [
                new UpdateOperation(
                    0,
                    UpdateOperationKind.Replace,
                    UpdateReleaseContract.WindowsApplicationPath,
                    true,
                    10,
                    Hash('a'),
                    UpdateReleaseContract.WindowsApplicationPath,
                    Hash('a'),
                    11,
                    Hash('b'),
                    states[0]),
                new UpdateOperation(
                    1,
                    UpdateOperationKind.Create,
                    "assets/new.bin",
                    false,
                    null,
                    null,
                    null,
                    null,
                    12,
                    Hash('c'),
                    states[1]),
                new UpdateOperation(
                    2,
                    UpdateOperationKind.ReplaceManifest,
                    UpdateReleaseContract.ReleaseManifestPath,
                    true,
                    13,
                    Hash('d'),
                    UpdateReleaseContract.ReleaseManifestPath,
                    Hash('d'),
                    14,
                    Hash('e'),
                    states[2])
            ]);
    }

    private static UpdateOperationJournal Advance(
        UpdateOperationJournal journal,
        int ordinal,
        UpdateOperationState state) =>
        journal with
        {
            Generation = journal.Generation + 1,
            Operations = journal.Operations
                .Select(
                    operation => operation.Ordinal == ordinal
                        ? operation with { State = state }
                        : operation)
                .ToArray()
        };

    private static UpdateOperationJournal WithOperation(
        UpdateOperationJournal journal,
        int ordinal,
        Func<UpdateOperation, UpdateOperation> mutate) =>
        journal with
        {
            Operations = journal.Operations
                .Select(
                    operation => operation.Ordinal == ordinal
                        ? mutate(operation)
                        : operation)
                .ToArray()
        };

    private static UpdateOperationState[] States(string states) =>
        states.Select(
                state => state switch
                {
                    'P' => UpdateOperationState.Planned,
                    'S' => UpdateOperationState.BackupStarted,
                    'X' => UpdateOperationState.BackupComplete,
                    'I' => UpdateOperationState.WriteStarted,
                    'W' => UpdateOperationState.WriteComplete,
                    _ => throw new ArgumentOutOfRangeException(nameof(states))
                })
            .ToArray();

    private static string Serialize(UpdateOperationJournal journal)
    {
        UpdateOperationJournalCodec.TrySerialize(journal, out var bytes).Should().BeTrue();
        return Encoding.UTF8.GetString(bytes);
    }

    private static byte[] SerializeBytes(UpdateOperationJournal journal)
    {
        UpdateOperationJournalCodec.TrySerialize(journal, out var bytes).Should().BeTrue();
        return bytes;
    }

    private static string CanonicalHash(UpdateOperationJournal journal) =>
        Convert.ToHexString(SHA256.HashData(SerializeBytes(journal)))
            .ToLowerInvariant();

    private static void AssertCanonicalSuccessor(
        UpdateOperationJournal? previous,
        UpdateOperationJournal next,
        string? previousSha256 = null)
    {
        var hash = previous is null
            ? previousSha256
            : CanonicalHash(previous);

        UpdateOperationJournalCodec.TryValidateCanonicalSuccessor(
                SerializeBytes(next),
                hash,
                out var parsed)
            .Should()
            .BeTrue();
        parsed.Should().BeEquivalentTo(next);
    }
    private static string Hash(char value) => new(value, 64);
}
