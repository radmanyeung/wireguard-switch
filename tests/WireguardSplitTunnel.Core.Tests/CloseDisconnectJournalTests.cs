using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class CloseDisconnectJournalTests : IDisposable
{
    private readonly string tempDirectory = Path.Combine(
        Path.GetTempPath(),
        "WireguardSplitTunnel.CloseDisconnectJournalTests",
        Guid.NewGuid().ToString("N"));

    private readonly string journalPath;

    public CloseDisconnectJournalTests()
    {
        Directory.CreateDirectory(tempDirectory);
        journalPath = Path.Combine(tempDirectory, "close-disconnect.json");
    }

    [Fact]
    public void Load_ReturnsNull_WhenJournalDoesNotExist()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);

        journal.Load().Should().BeNull();
    }

    [Fact]
    public void Load_LegacyPendingJournalWithoutProcessIdentity_RemainsReadableForFailClosedRecovery()
    {
        File.WriteAllText(journalPath,
            """
            {
              "OperationId": "891e29c2-72e5-49ee-902b-a338ee70c694",
              "Phase": 0,
              "Targets": [],
              "PendingEnable": "WireGuardTunnel$Office_2"
            }
            """);
        var journal = new FileCloseDisconnectJournal(journalPath);

        var loaded = journal.Load();

        loaded!.PendingEnable!.ServiceName.Should().Be("WireGuardTunnel$Office_2");
        loaded.PendingEnableProcess.Should().BeNull();
    }

    [Fact]
    public void SaveAndLoad_RoundTripsExactEntry()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);
        var entry = CreateEntry();

        journal.Save(entry);
        var loaded = journal.Load();

        loaded.Should().BeEquivalentTo(entry);
        loaded!.Targets.Select(target => target.ServiceName).Should().Equal(
            "WireGuardTunnel$SG",
            "WireGuardTunnel$external.tunnel-1");
        loaded.PendingEnable!.ServiceName.Should().Be("WireGuardTunnel$Office_2");
        loaded.PendingEnableProcess.Should().Be(new EnableTunnelProcessIdentity(731, 987654321));
    }

    [Fact]
    public void Save_SerializesOnlyOperationPhaseServiceNamesAndExactProcessIdentity()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);

        journal.Save(CreateEntry());

        using var document = JsonDocument.Parse(File.ReadAllText(journalPath));
        var root = document.RootElement;
        root.EnumerateObject().Select(property => property.Name).Should().BeEquivalentTo(
            "OperationId",
            "Phase",
            "Targets",
            "PendingEnable",
            "PendingEnableProcess");
        root.GetProperty("Targets").EnumerateArray()
            .Select(target => target.GetString())
            .Should().Equal(
                "WireGuardTunnel$SG",
                "WireGuardTunnel$external.tunnel-1");
        root.GetProperty("PendingEnable").GetString().Should().Be("WireGuardTunnel$Office_2");
        var process = root.GetProperty("PendingEnableProcess");
        process.EnumerateObject().Select(property => property.Name).Should().BeEquivalentTo(
            "ProcessId",
            "CreationTimeFileTimeUtc");
        process.GetProperty("ProcessId").GetInt32().Should().Be(731);
        process.GetProperty("CreationTimeFileTimeUtc").GetInt64().Should().Be(987654321);

        var json = root.GetRawText();
        json.Should().NotContain("PrivateKey");
        json.Should().NotContain("ConfigContents");
        json.Should().NotContain("SourcePath");
        json.Should().NotContain("Command");
        json.Should().NotContain("Stdout");
        json.Should().NotContain("Stderr");
        json.Should().NotContain("ImagePath");
        json.Should().NotContain("ProcessName");
    }

    [Fact]
    public void Save_ReplacesExistingJournalAndLeavesNoSiblingTempFiles()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);
        journal.Save(CreateEntry());
        var replacement = new CloseDisconnectJournalEntry(
            Guid.NewGuid(),
            CloseDisconnectJournalPhase.TargetsRecorded,
            [WindowsTunnelServiceIdentity.FromTunnelName("replacement")],
            null);

        journal.Save(replacement);

        journal.Load().Should().BeEquivalentTo(replacement);
        File.Exists(journalPath).Should().BeTrue();
        Directory.EnumerateFiles(tempDirectory, "*.tmp").Should().BeEmpty();
        Directory.EnumerateFiles(tempDirectory).Should().BeEquivalentTo(
            journalPath,
            journalPath + ".lock");
        new FileInfo(journalPath + ".lock").Length.Should().Be(0);
    }

    [Fact]
    public async Task SiblingLock_SerializesCompleteAndSave_SoStaleCompletionCannotDeleteReplacement()
    {
        var firstJournal = new FileCloseDisconnectJournal(journalPath);
        var secondJournal = new FileCloseDisconnectJournal(journalPath);
        var first = CreateEntry();
        var replacement = first with
        {
            OperationId = Guid.NewGuid(),
            Targets = [WindowsTunnelServiceIdentity.FromTunnelName("replacement")]
        };
        firstJournal.Save(first);
        var completionStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var saveStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        Task completion;
        Task save;
        bool completionBlocked;
        bool saveBlocked;
        using (var lockStream = new FileStream(
                   journalPath + ".lock",
                   FileMode.Open,
                   FileAccess.ReadWrite,
                   FileShare.None))
        {
            completion = Task.Run(() =>
            {
                completionStarted.SetResult();
                firstJournal.Complete(first.OperationId);
            });
            save = Task.Run(() =>
            {
                saveStarted.SetResult();
                secondJournal.Save(replacement);
            });

            await Task.WhenAll(completionStarted.Task, saveStarted.Task)
                .WaitAsync(TimeSpan.FromSeconds(5));
            await Task.Delay(200);
            completionBlocked = !completion.IsCompleted;
            saveBlocked = !save.IsCompleted;
        }

        await Task.WhenAll(completion, save).WaitAsync(TimeSpan.FromSeconds(5));

        completionBlocked.Should().BeTrue("completion must wait for the OS sibling lock");
        saveBlocked.Should().BeTrue("replacement must wait for the OS sibling lock");
        secondJournal.Load().Should().BeEquivalentTo(replacement);
        File.Exists(journalPath).Should().BeTrue();
        File.Exists(journalPath + ".lock").Should().BeTrue(
            "the empty lock artifact must not be deleted while another process may wait on it");
    }

    [Fact]
    public void Save_WhenFirstPublicationFails_CleansTempAndPreservesDestination()
    {
        Directory.CreateDirectory(journalPath);
        var journal = new FileCloseDisconnectJournal(journalPath);

        var save = () => journal.Save(CreateEntry());

        save.Should().Throw<IOException>();
        Directory.Exists(journalPath).Should().BeTrue();
        Directory.EnumerateFiles(tempDirectory, "*.tmp").Should().BeEmpty();
    }

    [Fact]
    public void Save_WhenReplacementPublicationFails_CleansTempAndPreservesOriginal()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);
        var original = CreateEntry();
        journal.Save(original);
        var originalJson = File.ReadAllText(journalPath);

        using (var destination = new FileStream(
                   journalPath,
                   FileMode.Open,
                   FileAccess.ReadWrite,
                   FileShare.None))
        {
            var save = () => journal.Save(original with { OperationId = Guid.NewGuid() });

            save.Should().Throw<IOException>();
            Directory.EnumerateFiles(tempDirectory, "*.tmp").Should().BeEmpty();
        }

        File.ReadAllText(journalPath).Should().Be(originalJson);
        journal.Load().Should().BeEquivalentTo(original);
    }

    [Fact]
    public void Complete_DeletesMatchingJournalAndSecondCompleteIsNoOp()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);
        var entry = CreateEntry();
        journal.Save(entry);

        journal.Complete(entry.OperationId);

        File.Exists(journalPath).Should().BeFalse();
        journal.Load().Should().BeNull();

        var secondComplete = () => journal.Complete(entry.OperationId);
        secondComplete.Should().NotThrow();
        File.Exists(journalPath).Should().BeFalse();
    }

    [Fact]
    public void Complete_WithMismatchedOperationId_DoesNotDeleteAnotherJournal()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);
        var entry = CreateEntry();
        journal.Save(entry);
        var originalJson = File.ReadAllText(journalPath);

        journal.Complete(Guid.NewGuid());

        File.Exists(journalPath).Should().BeTrue();
        File.ReadAllText(journalPath).Should().Be(originalJson);
        journal.Load().Should().BeEquivalentTo(entry);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("{}")]
    public void Load_RejectsMalformedJson_WithoutDeletingFile(string json)
    {
        File.WriteAllText(journalPath, json);
        var journal = new FileCloseDisconnectJournal(journalPath);

        var load = () => journal.Load();

        load.Should().Throw<InvalidDataException>();
        File.Exists(journalPath).Should().BeTrue();
        File.ReadAllText(journalPath).Should().Be(json);
    }

    [Theory]
    [MemberData(nameof(InvalidJournalJson))]
    public void Load_RejectsInvalidEntries_WithoutDeletingFile(string json)
    {
        File.WriteAllText(journalPath, json);
        var journal = new FileCloseDisconnectJournal(journalPath);

        var load = () => journal.Load();

        load.Should().Throw<InvalidDataException>();
        File.Exists(journalPath).Should().BeTrue();
        File.ReadAllText(journalPath).Should().Be(json);
    }

    [Fact]
    public void Save_RejectsDefaultOperationIdAndUndefinedPhase()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);
        var valid = CreateEntry();

        var saveDefaultId = () => journal.Save(valid with { OperationId = Guid.Empty });
        var saveUndefinedPhase = () => journal.Save(
            valid with { Phase = (CloseDisconnectJournalPhase)999 });

        saveDefaultId.Should().Throw<InvalidDataException>();
        saveUndefinedPhase.Should().Throw<InvalidDataException>();
        File.Exists(journalPath).Should().BeFalse();
    }

    [Fact]
    public void Save_RejectsMissingTargetsAndNullTargetIdentity()
    {
        var journal = new FileCloseDisconnectJournal(journalPath);
        var valid = CreateEntry();

        var saveNullTargets = () => journal.Save(valid with { Targets = null! });
        var saveNullTarget = () => journal.Save(valid with { Targets = [null!] });

        saveNullTargets.Should().Throw<InvalidDataException>();
        saveNullTarget.Should().Throw<InvalidDataException>();
        File.Exists(journalPath).Should().BeFalse();
    }

    [Fact]
    public void Complete_WithMalformedJournal_ThrowsAndPreservesUserData()
    {
        const string malformedJson = """{"OperationId":"not-a-guid","userData":"preserve"}""";
        File.WriteAllText(journalPath, malformedJson);
        var journal = new FileCloseDisconnectJournal(journalPath);

        var complete = () => journal.Complete(Guid.NewGuid());

        complete.Should().Throw<InvalidDataException>();
        File.Exists(journalPath).Should().BeTrue();
        File.ReadAllText(journalPath).Should().Be(malformedJson);
    }

    public static IEnumerable<object[]> InvalidJournalJson()
    {
        yield return [ValidJson().Replace("891e29c2-72e5-49ee-902b-a338ee70c694", "00000000-0000-0000-0000-000000000000", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"Phase\": 1", "\"Phase\": 999", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"WireGuardTunnel$SG\"", "\"not-a-tunnel-service\"", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"WireGuardTunnel$Office_2\"", "\"WireGuardTunnel$bad/name\"", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"Targets\": [", "\"Targets\": null,\"Ignored\": [", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"WireGuardTunnel$SG\"", "null", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"OperationId\":", "\"ConfigContents\": \"PrivateKey=secret\",\"OperationId\":", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"ProcessId\": 731", "\"ProcessId\": 0", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"CreationTimeFileTimeUtc\": 987654321", "\"CreationTimeFileTimeUtc\": 0", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"PendingEnable\": \"WireGuardTunnel$Office_2\"", "\"PendingEnable\": null", StringComparison.Ordinal)];
        yield return [ValidJson().Replace("\"ProcessId\": 731", "\"ProcessId\": 731,\"ImagePath\": \"secret\"", StringComparison.Ordinal)];
    }

    public void Dispose()
    {
        if (Directory.Exists(tempDirectory))
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    private static CloseDisconnectJournalEntry CreateEntry() =>
        new(
            Guid.Parse("891e29c2-72e5-49ee-902b-a338ee70c694"),
            CloseDisconnectJournalPhase.TargetsRecorded,
            [
                WindowsTunnelServiceIdentity.FromTunnelName("SG"),
                WindowsTunnelServiceIdentity.FromTunnelName("external.tunnel-1")
            ],
            WindowsTunnelServiceIdentity.FromTunnelName("Office_2"),
            new EnableTunnelProcessIdentity(731, 987654321));

    private static string ValidJson() =>
        """
        {
          "OperationId": "891e29c2-72e5-49ee-902b-a338ee70c694",
          "Phase": 1,
          "Targets": [
            "WireGuardTunnel$SG",
            "WireGuardTunnel$external.tunnel-1"
          ],
          "PendingEnable": "WireGuardTunnel$Office_2",
          "PendingEnableProcess": {
            "ProcessId": 731,
            "CreationTimeFileTimeUtc": 987654321
          }
        }
        """;
}
