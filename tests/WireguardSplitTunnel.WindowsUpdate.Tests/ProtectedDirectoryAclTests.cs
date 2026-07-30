using System.Security.AccessControl;
using System.Security.Principal;
using FluentAssertions;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ProtectedDirectoryAclTests
{
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    private static readonly SecurityIdentifier System =
        new(WellKnownSidType.LocalSystemSid, null);

    [Fact]
    public void WindowsNativeRootAccess_DefaultIsReadOnlyAndMutationAddsOnlyRequiredDirectoryRights()
    {
        const uint readControl = 0x00020000;
        const uint synchronize = 0x00100000;
        const uint fileReadAttributes = 0x00000080;
        const uint fileListDirectory = 0x00000001;
        const uint fileTraverse = 0x00000020;
        const uint fileWriteData = 0x00000002;
        const uint fileAddSubdirectory = 0x00000004;
        const uint fileDeleteChild = 0x00000040;
        var expectedReadOnly = readControl
            | synchronize
            | fileReadAttributes
            | fileListDirectory
            | fileTraverse;
        var expectedMutation = expectedReadOnly
            | fileWriteData
            | fileAddSubdirectory
            | fileDeleteChild;

        WindowsProtectedAclNativeFileSystem
            .GetRootDesiredAccess(
                requireWriteAccess: false)
            .Should().Be(expectedReadOnly);
        WindowsProtectedAclNativeFileSystem
            .GetRootDesiredAccess(
                requireWriteAccess: true)
            .Should().Be(expectedMutation);
    }

    [Fact]
    public void BuildDirectorySecurity_UsesTheExactProtectedSystemAndAdministratorsDescriptor()
    {
        var security = ProtectedDirectoryAcl.BuildDirectorySecurity();

        AssertCommonDescriptor(security);
        var rules = Rules(security);
        rules.Should().OnlyContain(rule =>
            rule.FileSystemRights == FileSystemRights.FullControl
            && rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit)
            && rule.PropagationFlags == PropagationFlags.None);
    }

    [Fact]
    public void BuildFileSecurity_UsesTheExactProtectedSystemAndAdministratorsDescriptor()
    {
        var security = ProtectedDirectoryAcl.BuildFileSecurity();

        AssertCommonDescriptor(security);
        var rules = Rules(security);
        rules.Should().OnlyContain(rule =>
            rule.FileSystemRights == FileSystemRights.FullControl
            && rule.InheritanceFlags == InheritanceFlags.None
            && rule.PropagationFlags == PropagationFlags.None);
    }

    [Fact]
    public void ValidateDescriptor_AcceptsOnlyTheMatchingDirectoryAndFileShapes()
    {
        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(
            ProtectedDirectoryAcl.BuildDirectorySecurity()).Should().BeTrue();
        ProtectedDirectoryAcl.HasExactFileDescriptor(
            ProtectedDirectoryAcl.BuildFileSecurity()).Should().BeTrue();

        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(
            ProtectedDirectoryAcl.BuildFileSecurity()).Should().BeFalse();
        ProtectedDirectoryAcl.HasExactFileDescriptor(
            ProtectedDirectoryAcl.BuildDirectorySecurity()).Should().BeFalse();
    }

    [Fact]
    public void ValidateDescriptor_RejectsWrongOwnerInheritanceExtraIdentityAndWeakerRights()
    {
        var wrongOwner = ProtectedDirectoryAcl.BuildDirectorySecurity();
        wrongOwner.SetOwner(Administrators);

        var inherited = new DirectorySecurity();
        inherited.SetOwner(System);
        inherited.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
        inherited.AddAccessRule(DirectoryRule(Administrators, FileSystemRights.FullControl));
        inherited.AddAccessRule(DirectoryRule(System, FileSystemRights.FullControl));

        var extraIdentity = ProtectedDirectoryAcl.BuildDirectorySecurity();
        extraIdentity.AddAccessRule(DirectoryRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.FullControl));

        var weaker = new DirectorySecurity();
        weaker.SetOwner(System);
        weaker.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        weaker.AddAccessRule(DirectoryRule(Administrators, FileSystemRights.Modify));
        weaker.AddAccessRule(DirectoryRule(System, FileSystemRights.FullControl));

        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(wrongOwner).Should().BeFalse();
        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(inherited).Should().BeFalse();
        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(extraIdentity).Should().BeFalse();
        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(weaker).Should().BeFalse();
    }

    [Fact]
    public void ValidateDescriptor_RejectsCallbackAndObjectAces()
    {
        var callback = SecurityFromSddl(
            "O:SYD:P"
            + "(XA;OICI;FA;;;SY;(@USER.Department == \"Finance\"))"
            + "(A;OICI;FA;;;BA)");

        var objectAcl = new RawAcl(GenericAcl.AclRevisionDS, 2);
        objectAcl.InsertAce(
            0,
            new ObjectAce(
                AceFlags.ContainerInherit | AceFlags.ObjectInherit,
                AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl,
                System,
                ObjectAceFlags.ObjectAceTypePresent,
                Guid.NewGuid(),
                Guid.Empty,
                isCallback: false,
                opaque: null));
        objectAcl.InsertAce(
            1,
            new CommonAce(
                AceFlags.ContainerInherit | AceFlags.ObjectInherit,
                AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl,
                Administrators,
                isCallback: false,
                opaque: null));
        var objectAce = SecurityFromRawAcl(objectAcl);

        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(callback)
            .Should().BeFalse();
        ProtectedDirectoryAcl.HasExactDirectoryDescriptor(objectAce)
            .Should().BeFalse();
    }

    [Fact]
    public void OpenNewProtectedFile_RejectsAWeakImmediateParent()
    {
        using var fixture = new AclFixture();

        using var result = fixture.Acl.OpenNewProtectedFile(
            Path.Combine(fixture.Root, "transaction.json"));

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            ProtectedAclError.SecurityMismatch);
    }

    [Fact]
    public void OpenNewProtectedFile_CreatesUnderThePinnedParentAfterNamespaceSwap()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        using var result = acl.OpenNewProtectedFile(
            @"C:\safe\protected\transaction.json");

        result.Success.Should().BeTrue();
        result.Stream.Should().NotBeNull();
        native.NamespaceSwapTriggered.Should().BeTrue();
        native.CreatedParentIdentity.Should().Be(
            native.ProtectedParentIdentity);
        native.CreatedOutsidePinnedParent.Should().BeFalse();
        native.Requests.Should().OnlyContain(request =>
            request.OpenReparsePoint && !request.ShareDelete);
    }

    [Fact]
    public void EnsureProtectedDirectory_CreatesUnderThePinnedParentAfterJunctionSwap()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        var result = acl.EnsureProtectedDirectory(
            @"C:\safe\protected\child");

        result.Success.Should().BeTrue();
        result.Created.Should().BeTrue();
        native.NamespaceSwapTriggered.Should().BeTrue();
        native.CreatedParentIdentity.Should().Be(
            native.ProtectedParentIdentity);
        native.CreatedOutsidePinnedParent.Should().BeFalse();
        native.Requests.Should().OnlyContain(request =>
            request.OpenReparsePoint && !request.ShareDelete);
    }

    [Fact]
    public void EnsureProtectedDirectory_RejectsAWeakExistingDirectoryWithoutRepairingIt()
    {
        using var fixture = new AclFixture();
        var path = Path.Combine(fixture.Root, "weak");
        Directory.CreateDirectory(path);
        var before = new DirectorySecurity(
            path,
            AccessControlSections.Owner | AccessControlSections.Access)
            .GetSecurityDescriptorBinaryForm();

        var result = fixture.Acl.EnsureProtectedDirectory(path);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(ProtectedAclError.SecurityMismatch);
        new DirectorySecurity(
                path,
                AccessControlSections.Owner | AccessControlSections.Access)
            .GetSecurityDescriptorBinaryForm()
            .Should().Equal(before);
    }

    [Fact]
    public void ValidateProtectedFile_RejectsAWeakExistingFile()
    {
        using var fixture = new AclFixture();
        var path = Path.Combine(fixture.Root, "weak.json");
        File.WriteAllText(path, "{}");

        var result = fixture.Acl.ValidateProtectedFile(path);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(ProtectedAclError.SecurityMismatch);
    }

    [Fact]
    public void EnsureProtectedDirectory_RejectsFilesAndReparsePoints()
    {
        using var fixture = new AclFixture();
        var file = Path.Combine(fixture.Root, "file");
        File.WriteAllText(file, "not a directory");

        fixture.Acl.EnsureProtectedDirectory(file).Error
            .Should().Be(ProtectedAclError.UnsafePath);

        var target = Path.Combine(fixture.Root, "target");
        var link = Path.Combine(fixture.Root, "link");
        Directory.CreateDirectory(target);
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return;
        }

        fixture.Acl.EnsureProtectedDirectory(link).Error
            .Should().Be(ProtectedAclError.UnsafePath);
    }

    [Fact(Skip = "Requires elevated Windows privileged CI.")]
    public void EnsureProtectedDirectory_CreatesAnExactDescriptor_WhenTheTokenCanAssignSystemOwner()
    {
        using var fixture = new AclFixture();
        var path = Path.Combine(fixture.Root, "protected");

        var result = fixture.Acl.EnsureProtectedDirectory(path);
        result.Success.Should().BeTrue();
        result.Created.Should().BeTrue();
        fixture.Acl.ValidateProtectedDirectory(path).Success.Should().BeTrue();
    }

    [Fact(Skip = "Requires elevated Windows privileged CI.")]
    public void OpenNewProtectedFile_CreatesAnExactDescriptor_WhenTheTokenCanAssignSystemOwner()
    {
        using var fixture = new AclFixture();
        var parent = Path.Combine(fixture.Root, "protected-parent");
        var parentResult = fixture.Acl.EnsureProtectedDirectory(parent);
        parentResult.Success.Should().BeTrue();
        var path = Path.Combine(parent, "state.json");
        using var result = fixture.Acl.OpenNewProtectedFile(path);

        result.Success.Should().BeTrue();
        result.Stream.Should().NotBeNull();
        result.Stream!.WriteByte(1);
        result.Stream.Flush(flushToDisk: true);
        result.Stream.Dispose();
        fixture.Acl.ValidateProtectedFile(path).Success.Should().BeTrue();
    }

    [Fact]
    public void InstalledReleasePolicy_RequiresTheExactReadableRootShape()
    {
        var installed = ProtectedDirectoryAcl
            .BuildInstalledRootSecurity()
            .GetSecurityDescriptorBinaryForm();
        var transaction = ProtectedDirectoryAcl
            .BuildDirectorySecurity()
            .GetSecurityDescriptorBinaryForm();

        ProtectedDirectoryInspectionPolicy.InstalledRelease
            .IsValidRoot(installed).Should().BeTrue();
        ProtectedDirectoryInspectionPolicy.InstalledRelease
            .IsValidRoot(transaction).Should().BeFalse();
        ProtectedDirectoryInspectionPolicy.Transaction
            .IsValidRoot(transaction).Should().BeTrue();
        ProtectedDirectoryInspectionPolicy.Transaction
            .IsValidRoot(installed).Should().BeFalse();
    }

    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")]
    public void InstalledReleaseParentAuthority_AcceptsOnlyTrustedOwners(
        string ownerSid)
    {
        var descriptor = ParentAuthorityDescriptor(
            new SecurityIdentifier(ownerSid),
            new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl,
                System,
                isCallback: false,
                opaque: null));

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                descriptor)
            .Should().BeTrue();
    }

    [Fact]
    public void InstalledReleaseParentAuthority_RejectsUnprotectedNonCanonicalOrUntrustedOwnership()
    {
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            null);
        var trustedAce = new CommonAce(
            AceFlags.None,
            AceQualifier.AccessAllowed,
            (int)FileSystemRights.FullControl,
            System,
            isCallback: false,
            opaque: null);
        var unprotected = ParentAuthorityDescriptor(
            System,
            ControlFlags.DiscretionaryAclPresent
                | ControlFlags.SelfRelative,
            trustedAce);
        var nonCanonical = ParentAuthorityDescriptor(
            System,
            new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x00000001,
                users,
                isCallback: false,
                opaque: null),
            new CommonAce(
                AceFlags.None,
                AceQualifier.AccessDenied,
                0x00000001,
                users,
                isCallback: false,
                opaque: null));
        var untrustedOwner = ParentAuthorityDescriptor(
            users,
            trustedAce);

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                unprotected)
            .Should().BeFalse();
        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                nonCanonical)
            .Should().BeFalse();
        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                untrustedOwner)
            .Should().BeFalse();
    }

    [Theory]
    [InlineData(0x00000002)]
    [InlineData(0x00000004)]
    [InlineData(0x00000040)]
    [InlineData(0x00010000)]
    [InlineData(0x00040000)]
    [InlineData(0x00080000)]
    [InlineData(0x10000000)]
    [InlineData(0x40000000)]
    public void InstalledReleaseParentAuthority_RejectsUntrustedEffectiveMutationRights(
        int dangerousMask)
    {
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            null);
        var effective = ParentAuthorityDescriptor(
            System,
            new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                dangerousMask,
                users,
                isCallback: false,
                opaque: null));
        var inheritOnly = ParentAuthorityDescriptor(
            System,
            new CommonAce(
                AceFlags.ContainerInherit
                    | AceFlags.ObjectInherit
                    | AceFlags.InheritOnly,
                AceQualifier.AccessAllowed,
                dangerousMask,
                users,
                isCallback: false,
                opaque: null));

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                effective)
            .Should().BeFalse();
        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                inheritOnly)
            .Should().BeTrue();
    }

    [Fact]
    public void InstalledReleaseParentAuthority_RejectsCallbackAces()
    {
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            null);
        var descriptor = ParentAuthorityDescriptor(
            System,
            new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x00000002,
                users,
                isCallback: true,
                opaque: null));

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                descriptor)
            .Should().BeFalse();
    }

    [Fact]
    public void InstalledReleaseParentAuthority_RejectsObjectAces()
    {
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            null);
        var descriptor = ParentAuthorityDescriptor(
            System,
            new ObjectAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x00000002,
                users,
                ObjectAceFlags.ObjectAceTypePresent,
                Guid.Parse("5f491958-998a-4a25-bd84-982c8af964a2"),
                Guid.Empty,
                isCallback: false,
                opaque: null));

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                descriptor)
            .Should().BeFalse();
    }

    [Fact]
    public void InstalledReleaseParentAuthority_RejectsOpaqueAces()
    {
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            null);
        var descriptor = ParentAuthorityDescriptor(
            System,
            new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                0x00000002,
                users,
                isCallback: true,
                opaque: [0, 0, 0, 0]));

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                descriptor)
            .Should().BeFalse();
    }

    [Fact]
    public void InstalledReleaseParentAuthority_RejectsSystemAuditAces()
    {
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            null);
        var descriptor = ParentAuthorityDescriptor(
            System,
            new CommonAce(
                AceFlags.SuccessfulAccess,
                AceQualifier.SystemAudit,
                0x00000002,
                users,
                isCallback: false,
                opaque: null));

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                descriptor)
            .Should().BeFalse();
    }

    [Fact]
    public void InstalledReleaseParentAuthority_RejectsSystemAlarmAces()
    {
        var users = new SecurityIdentifier(
            WellKnownSidType.BuiltinUsersSid,
            null);
        var descriptor = ParentAuthorityDescriptor(
            System,
            new CommonAce(
                AceFlags.None,
                AceQualifier.SystemAlarm,
                0x00000002,
                users,
                isCallback: false,
                opaque: null));

        ProtectedDirectoryAcl.HasTrustedInstallParentDescriptor(
                descriptor)
            .Should().BeFalse();
    }

    [Fact]
    public void InstalledApplicationLaunchLease_PreventsNamespaceSwapUntilDisposed()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\WireguardSplitTunnel",
            installedRelease: true);
        native.AddProtectedFile(
            @"WireguardSplitTunnel\WireguardSplitTunnel.App.exe",
            [1, 2, 3, 4]);
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);
        var applicationPath =
            @"C:\safe\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe";

        var opened = acl.OpenInstalledApplicationForLaunch(
            @"C:\safe",
            @"C:\safe\WireguardSplitTunnel",
            applicationPath);
        try
        {
            opened.Success.Should().BeTrue();
            opened.Lease.Should().NotBeNull();
            opened.Lease!.ApplicationPath.Should().Be(
                applicationPath);
            native.TrySwapProtectedNamespace().Should().BeFalse();
            opened.Lease.Revalidate().Should().BeTrue();
            native.Requests.Should().OnlyContain(request =>
                request.OpenReparsePoint
                && !request.ShareDelete);
        }
        finally
        {
            opened.Dispose();
        }

        native.TrySwapProtectedNamespace().Should().BeTrue();
    }

    [Theory]
    [InlineData(InstalledApplicationPin.ProgramFilesParent, NamespaceMutation.Rename)]
    [InlineData(InstalledApplicationPin.ProgramFilesParent, NamespaceMutation.Delete)]
    [InlineData(InstalledApplicationPin.InstalledRoot, NamespaceMutation.Rename)]
    [InlineData(InstalledApplicationPin.InstalledRoot, NamespaceMutation.Delete)]
    [InlineData(InstalledApplicationPin.ApplicationFile, NamespaceMutation.Rename)]
    [InlineData(InstalledApplicationPin.ApplicationFile, NamespaceMutation.Delete)]
    public void InstalledApplicationLaunchLease_BlocksRenameAndDeleteForEveryPinUntilDisposed(
        InstalledApplicationPin pin,
        NamespaceMutation mutation)
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\WireguardSplitTunnel",
            installedRelease: true);
        native.AddProtectedFile(
            @"WireguardSplitTunnel\WireguardSplitTunnel.App.exe",
            [1, 2, 3, 4]);
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);
        var opened = acl.OpenInstalledApplicationForLaunch(
            @"C:\safe",
            @"C:\safe\WireguardSplitTunnel",
            @"C:\safe\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe");
        try
        {
            opened.Success.Should().BeTrue();
            opened.Lease.Should().NotBeNull();
            native.HasNoDeleteSharePin(pin).Should().BeTrue();
            native.TryMutatePinnedLaunchNode(pin, mutation)
                .Should().BeFalse();
            opened.Lease!.Revalidate().Should().BeTrue();
        }
        finally
        {
            opened.Dispose();
        }

        native.HasNoDeleteSharePin(pin).Should().BeFalse();
        native.TryMutatePinnedLaunchNode(pin, mutation)
            .Should().BeTrue();
    }

    [Fact]
    public void InspectAndRead_RetainPinnedHandlesAcrossANamespaceSwap()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        native.AddProtectedFile(
            @"managed\app.exe",
            [1, 2, 3, 4]);
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        using var inspected = acl.InspectProtectedDirectory(
            @"C:\safe\protected",
            ProtectedDirectoryInspectionPolicy.Transaction);
        inspected.Success.Should().BeTrue();
        inspected.Lease!.Identity.Should().Be(
            native.ProtectedParentIdentity);

        using var read = acl.OpenProtectedFileForRead(
            inspected.Lease,
            @"managed\app.exe",
            ProtectedDirectoryInspectionPolicy.Transaction);
        read.Success.Should().BeTrue();
        inspected.Dispose();
        native.SwapProtectedNamespace();
        read.Lease!.TryReadAllBytes(4, out var bytes)
            .Should().BeTrue();
        bytes.Should().Equal(1, 2, 3, 4);
        read.Lease.Revalidate().Should().BeTrue();
        native.OpenedOutsidePinnedParent.Should().BeFalse();
    }

    [Fact]
    public void EnumerateProtectedDirectory_ReturnsPinnedRecursiveFileLeases()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        native.AddProtectedFile("root.json", [1]);
        native.AddProtectedFile(@"nested\child.bin", [2, 3]);
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        using var inspected = acl.InspectProtectedDirectory(
            @"C:\safe\protected",
            ProtectedDirectoryInspectionPolicy.Transaction);
        using var enumeration = acl.EnumerateProtectedDirectory(
            inspected.Lease!,
            ProtectedDirectoryInspectionPolicy.Transaction,
            maximumEntries: 8);

        enumeration.Success.Should().BeTrue();
        enumeration.Lease!.Files.Select(file => file.RelativePath)
            .Should().Equal("nested/child.bin", "root.json");
        enumeration.Lease.Directories.Should().ContainSingle(
            directory => directory.RelativePath == "nested"
                && directory.Identity.IsValid
                && directory.SecurityDescriptor.Length > 0);

        using var bounded = acl.EnumerateProtectedDirectory(
            inspected.Lease!,
            ProtectedDirectoryInspectionPolicy.Transaction,
            maximumEntries: 2);
        bounded.Success.Should().BeFalse();
        bounded.Error.Should().Be(ProtectedAclError.UnsafePath);
        inspected.Dispose();

        native.SwapProtectedNamespace();
        enumeration.Lease.Files.Should().OnlyContain(file =>
            file.Revalidate());
        enumeration.Lease.Files.Single(file =>
                file.RelativePath == "nested/child.bin")
            .TryReadAllBytes(2, out var bytes)
            .Should().BeTrue();
        bytes.Should().Equal(2, 3);
    }

    [Fact]
    public void ProductionReadLease_DuplicatesTheStreamAndKeepsThePinAlive()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "WireguardSplitTunnel.WindowsUpdate.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "state.bin");
        File.WriteAllBytes(path, [7, 8, 9]);
        var policy = new ProtectedDirectoryInspectionPolicy(
            _ => true,
            (_, _) => true);
        var acl = new ProtectedDirectoryAcl(
            new WindowsProtectedAclNativeFileSystem(),
            _ => DriveType.Fixed);

        try
        {
            var inspected = acl.InspectProtectedDirectory(
                root,
                policy);
            try
            {
                inspected.Success.Should().BeTrue();
                var read = acl.OpenProtectedFileForRead(
                    inspected.Lease!,
                    "state.bin",
                    policy);
                try
                {
                    read.Success.Should().BeTrue();
                    read.Lease!.TryReadAllBytes(3, out var bytes)
                        .Should().BeTrue();
                    bytes.Should().Equal(7, 8, 9);
                    read.Lease.Revalidate().Should().BeTrue();
                    read.Lease.Revalidate().Should().BeTrue();
                    read.Lease.Stream.Dispose();
                    read.Lease.Revalidate().Should().BeTrue();
                }
                finally
                {
                    read.Dispose();
                }
            }
            finally
            {
                inspected.Dispose();
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
    [Fact]
    public void ProtectedFileMutation_UsesIdentityAndExactBytesForCas()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var expectedIdentity = native.AddProtectedFile(
            "state.json",
            [1, 2]);
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        var conflict = acl.CompareExchangeProtectedFile(
            @"C:\safe\protected\state.json",
            expectedIdentity,
            expectedBytes: new byte[] { 9, 9 },
            replacementBytes: new byte[] { 3, 4 });
        conflict.Outcome.Should().Be(
            ProtectedFileCompareExchangeOutcome.Conflict);

        native.Events.Clear();
        var committed = acl.CompareExchangeProtectedFile(
            @"C:\safe\protected\state.json",
            expectedIdentity,
            expectedBytes: new byte[] { 1, 2 },
            replacementBytes: new byte[] { 3, 4 });
        committed.Outcome.Should().Be(
            ProtectedFileCompareExchangeOutcome.Committed);
        var fileFlush = native.Events.IndexOf("flush-file");
        var rename = native.Events.IndexOf("rename");
        var directoryFlush = native.Events.IndexOf(
            "flush-directory");
        var postVerify = native.Events.LastIndexOf(
            "open-read");
        fileFlush.Should().BeGreaterThanOrEqualTo(0);
        rename.Should().BeGreaterThan(fileFlush);
        directoryFlush.Should().BeGreaterThan(rename);
        postVerify.Should().BeGreaterThan(directoryFlush);
        native.ReadProtectedFile("state.json")
            .Should().Equal(3, 4);
        native.CreatedParentIdentity.Should().Be(
            native.ProtectedParentIdentity);
        native.Requests.Should().Contain(request =>
            request.RequireWriteAccess);
    }

    [Fact]
    public void ProtectedFileMutation_KeepsNoDeleteShareDestinationPinnedThroughRename()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var id = native.AddProtectedFile(
            "state.json",
            [1, 2]);
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        var committed = acl.CompareExchangeProtectedFile(
            @"C:\safe\protected\state.json",
            id,
            new byte[] { 1, 2 },
            new byte[] { 3, 4 });

        committed.Outcome.Should().Be(
            ProtectedFileCompareExchangeOutcome.Committed);
        var rename = native.Events.IndexOf("rename");
        var firstDestinationDispose = native.Events.IndexOf(
            "dispose:state.json");
        rename.Should().BeGreaterThanOrEqualTo(0);
        firstDestinationDispose.Should().BeGreaterThan(rename);
    }

    [Fact]
    public void ProtectedFileMutation_RenameFlushFailurePreservesChangedNamespaceAndReturnsFailed()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var expectedIdentity = native.AddProtectedFile(
            "state.json",
            [1, 2]);
        native.FailNextDirectoryFlush = true;
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        var failed = acl.CompareExchangeProtectedFile(
            @"C:\safe\protected\state.json",
            expectedIdentity,
            expectedBytes: new byte[] { 1, 2 },
            replacementBytes: new byte[] { 3, 4 });

        failed.Outcome.Should().Be(
            ProtectedFileCompareExchangeOutcome.Failed);
        failed.Error.Should().Be(ProtectedAclError.IoFailure);
        native.ReadProtectedFile("state.json")
            .Should().Equal(3, 4);
        native.Events.Should().ContainInOrder(
            "flush-file",
            "rename",
            "flush-directory");
        native.Events.Should().NotContain("delete");
    }

    [Fact]
    public void ProtectedDirectoryTreeAndDelete_StayHandleRelativeAndIdentityBound()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        using var ensured = acl.EnsureProtectedDirectoryTree(
            @"C:\safe\protected",
            ["candidate", "nested"]);
        ensured.Success.Should().BeTrue();
        ensured.Created.Should().BeTrue();
        var identity = ensured.Lease!.Identity;
        ensured.Dispose();
        native.RestoreProtectedNamespace();

        acl.DeleteProtectedDirectory(
                @"C:\safe\protected\candidate\nested",
                identity with { FileIdLow = identity.FileIdLow + 1 })
            .Outcome.Should().Be(
                ProtectedFileMutationOutcome.Conflict);
        native.Events.Clear();
        acl.DeleteProtectedDirectory(
                @"C:\safe\protected\candidate\nested",
                identity)
            .Outcome.Should().Be(
                ProtectedFileMutationOutcome.Committed);
        native.Events.Should().ContainInOrder(
            "enumerate",
            "delete",
            "dispose:nested",
            "flush-directory");

        native.ContainsProtectedEntry(@"candidate\nested")
            .Should().BeFalse();
        native.Requests.Should().OnlyContain(request =>
            request.OpenReparsePoint && !request.ShareDelete);
        native.Requests.Should().Contain(request =>
            request.RequireDeleteAccess);
    }

    [Fact]
    public void DeleteProtectedFile_DirectoryFlushFailureReturnsFailedAfterTheTargetIsDisposed()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var identity = native.AddProtectedFile(
            "state.json",
            [1, 2]);
        native.FailNextDirectoryFlush = true;
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        var result = acl.DeleteProtectedFile(
            @"C:\safe\protected\state.json",
            identity);

        result.Outcome.Should().Be(
            ProtectedFileMutationOutcome.Failed);
        result.Error.Should().Be(ProtectedAclError.IoFailure);
        native.Events.Should().ContainInOrder(
            "delete",
            "dispose:state.json",
            "flush-directory");
        native.ContainsProtectedEntry("state.json")
            .Should().BeFalse();
    }

    [Fact]
    public void DeleteProtectedFile_PostVerificationFailureDoesNotReturnCommitted()
    {
        using var native = new InterleavingProtectedAclNative(
            @"C:\safe\protected");
        var identity = native.AddProtectedFile(
            "state.json",
            [1, 2]);
        native.FailNextMissingOpenWithIo = true;
        var acl = new ProtectedDirectoryAcl(
            native,
            _ => DriveType.Fixed);

        var result = acl.DeleteProtectedFile(
            @"C:\safe\protected\state.json",
            identity);

        result.Outcome.Should().Be(
            ProtectedFileMutationOutcome.Failed);
        result.Error.Should().Be(ProtectedAclError.IoFailure);
        native.Events.Should().ContainInOrder(
            "delete",
            "dispose:state.json",
            "flush-directory");
        native.ContainsProtectedEntry("state.json")
            .Should().BeFalse();
    }
    private static void AssertCommonDescriptor(FileSystemSecurity security)
    {
        security.AreAccessRulesProtected.Should().BeTrue();
        security.AreAccessRulesCanonical.Should().BeTrue();
        security.GetOwner(typeof(SecurityIdentifier)).Should().Be(System);

        var rules = Rules(security);
        rules.Should().HaveCount(2);
        rules.Should().OnlyContain(rule =>
            !rule.IsInherited
            && rule.AccessControlType == AccessControlType.Allow);
        rules.Select(rule => rule.IdentityReference)
            .Should().BeEquivalentTo([Administrators, System]);
    }

    private static DirectorySecurity SecurityFromSddl(string sddl)
    {
        var raw = new RawSecurityDescriptor(sddl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(bytes);
        return security;
    }

    private static DirectorySecurity SecurityFromRawAcl(RawAcl acl)
    {
        var raw = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent
                | ControlFlags.DiscretionaryAclProtected
                | ControlFlags.SelfRelative,
            System,
            group: null,
            systemAcl: null,
            discretionaryAcl: acl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        var security = new DirectorySecurity();
        security.SetSecurityDescriptorBinaryForm(bytes);
        return security;
    }

    private static byte[] ParentAuthorityDescriptor(
        SecurityIdentifier owner,
        params GenericAce[] aces) =>
        ParentAuthorityDescriptor(
            owner,
            ControlFlags.DiscretionaryAclPresent
                | ControlFlags.DiscretionaryAclProtected
                | ControlFlags.SelfRelative,
            aces);

    private static byte[] ParentAuthorityDescriptor(
        SecurityIdentifier owner,
        ControlFlags controlFlags,
        params GenericAce[] aces)
    {
        var revision = aces.Any(ace => ace is ObjectAce)
            ? GenericAcl.AclRevisionDS
            : GenericAcl.AclRevision;
        var acl = new RawAcl(revision, aces.Length);
        for (var index = 0; index < aces.Length; index++)
        {
            acl.InsertAce(index, aces[index]);
        }

        var raw = new RawSecurityDescriptor(
            controlFlags,
            owner,
            group: null,
            systemAcl: null,
            discretionaryAcl: acl);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static IReadOnlyList<FileSystemAccessRule> Rules(
        FileSystemSecurity security) =>
        security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                targetType: typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();

    private static FileSystemAccessRule DirectoryRule(
        SecurityIdentifier identity,
        FileSystemRights rights) =>
        new(
            identity,
            rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);

    public enum InstalledApplicationPin
    {
        ProgramFilesParent,
        InstalledRoot,
        ApplicationFile
    }

    public enum NamespaceMutation
    {
        Rename,
        Delete
    }

    private sealed class InterleavingProtectedAclNative
        : IProtectedAclNativeFileSystem,
          IDisposable
    {
        private readonly FakeNode _root;
        private readonly FakeNode _safe;
        private readonly FakeNode _protectedParent;
        private readonly FakeNode _outside;
        private readonly bool _installedRelease;
        private ulong _nextIdentity = 10;
        private readonly List<string> _backingPaths = [];

        public InterleavingProtectedAclNative(
            string protectedParentPath,
            bool installedRelease = false)
        {
            _installedRelease = installedRelease;
            var directoryDescriptor = ProtectedDirectoryAcl
                .BuildDirectorySecurity()
                .GetSecurityDescriptorBinaryForm();
            _root = CreateNode(
                @"C:\",
                isDirectory: true,
                directoryDescriptor);
            _safe = CreateNode(
                @"C:\safe",
                isDirectory: true,
                directoryDescriptor);
            _protectedParent = CreateNode(
                protectedParentPath,
                isDirectory: true,
                installedRelease
                    ? ProtectedDirectoryAcl
                        .BuildInstalledRootSecurity()
                        .GetSecurityDescriptorBinaryForm()
                    : directoryDescriptor);
            _outside = CreateNode(
                @"C:\outside",
                isDirectory: true,
                directoryDescriptor);
            _root.Children.Add("safe", _safe);
            _safe.Parent = _root;
            _safe.Name = "safe";
            var protectedName = Path.GetFileName(
                protectedParentPath.TrimEnd(
                    Path.DirectorySeparatorChar));
            _safe.Children.Add(protectedName, _protectedParent);
            _protectedParent.Parent = _safe;
            _protectedParent.Name = protectedName;
            _outside.Name = "outside";
        }

        public List<ProtectedAclNativeOpenRequest> Requests { get; } = [];
        public bool FailNextDirectoryFlush { get; set; }
        public bool NamespaceSwapTriggered { get; private set; }
        public bool FailNextMissingOpenWithIo { get; set; }
        public ProtectedFileIdentity128? CreatedParentIdentity { get; private set; }
        public bool CreatedOutsidePinnedParent { get; private set; }
        public bool OpenedOutsidePinnedParent { get; private set; }
        public List<string> Events { get; } = [];
        public ProtectedFileIdentity128 ProtectedParentIdentity =>
            _protectedParent.Snapshot.Identity;

        public ProtectedFileIdentity128 AddProtectedFile(
            string relativePath,
            byte[] bytes)
        {
            var segments = relativePath.Split(
                ['\\', '/'],
                StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0)
            {
                throw new ArgumentException(
                    "A protected relative file path is required.",
                    nameof(relativePath));
            }

            var current = _protectedParent;
            var directoryDescriptor = _installedRelease
                ? InstalledDescendantDescriptor(directory: true)
                : ProtectedDirectoryAcl
                    .BuildDirectorySecurity()
                    .GetSecurityDescriptorBinaryForm();
            for (var index = 0;
                 index < segments.Length - 1;
                 index++)
            {
                if (!current.Children.TryGetValue(
                        segments[index],
                        out var child))
                {
                    child = CreateNode(
                        Path.Combine(
                            current.Snapshot.FinalPath,
                            segments[index]),
                        isDirectory: true,
                        directoryDescriptor);
                    child.Parent = current;
                    child.Name = segments[index];
                    current.Children.Add(segments[index], child);
                }

                current = child;
            }

            var fileDescriptor = _installedRelease
                ? InstalledDescendantDescriptor(directory: false)
                : ProtectedDirectoryAcl
                    .BuildFileSecurity()
                    .GetSecurityDescriptorBinaryForm();
            var file = CreateNode(
                Path.Combine(
                    current.Snapshot.FinalPath,
                    segments[^1]),
                isDirectory: false,
                fileDescriptor);
            file.Parent = current;
            file.Name = segments[^1];
            file.WriteContent(bytes);
            current.Children.Add(segments[^1], file);
            return file.Snapshot.Identity;
        }

        public void SwapProtectedNamespace()
        {
            NamespaceSwapTriggered = true;
            _safe.Children["protected"] = _outside;
        }

        public bool TrySwapProtectedNamespace()
        {
            if (_protectedParent.NoDeleteShareHandleCount != 0)
            {
                return false;
            }

            NamespaceSwapTriggered = true;
            _safe.Children[_protectedParent.Name] = _outside;
            return true;
        }

        public bool HasNoDeleteSharePin(
            InstalledApplicationPin pin) =>
            ResolvePinnedLaunchNode(pin)
                .NoDeleteShareHandleCount != 0;

        public bool TryMutatePinnedLaunchNode(
            InstalledApplicationPin pin,
            NamespaceMutation mutation)
        {
            var node = ResolvePinnedLaunchNode(pin);
            Events.Add(
                $"{mutation.ToString().ToLowerInvariant()}-attempt:{pin}");
            if (node.NoDeleteShareHandleCount != 0
                || node.Deleted
                || node.Parent is null)
            {
                return false;
            }

            if (mutation == NamespaceMutation.Rename)
            {
                var originalName = node.Name;
                var movedName = $"{originalName}.moved";
                node.Parent.Children.Remove(originalName);
                node.Name = movedName;
                node.SetFinalPath(
                    Path.Combine(
                        node.Parent.Snapshot.FinalPath,
                        movedName));
                node.Parent.Children.Add(movedName, node);
            }
            else
            {
                node.Parent.Children.Remove(node.Name);
                node.Deleted = true;
                node.DeleteBackingFile();
            }

            Events.Add(
                $"{mutation.ToString().ToLowerInvariant()}-committed:{pin}");
            return true;
        }

        public byte[] ReadProtectedFile(string relativePath) =>
            ResolveProtectedEntry(relativePath).ReadContent();
        public void RestoreProtectedNamespace()
        {
            _safe.Children["protected"] = _protectedParent;
        }


        public bool ContainsProtectedEntry(string relativePath) =>
            TryResolveProtectedEntry(relativePath, out _);

        private FakeNode ResolveProtectedEntry(string relativePath) =>
            TryResolveProtectedEntry(relativePath, out var node)
                ? node!
                : throw new FileNotFoundException(relativePath);

        private bool TryResolveProtectedEntry(
            string relativePath,
            out FakeNode? node)
        {
            node = _protectedParent;
            foreach (var segment in relativePath.Split(
                ['\\', '/'],
                StringSplitOptions.RemoveEmptyEntries))
            {
                if (!node.Children.TryGetValue(segment, out var child))
                {
                    node = null;
                    return false;
                }

                node = child;
            }

            return true;
        }

        private FakeNode ResolvePinnedLaunchNode(
            InstalledApplicationPin pin) =>
            pin switch
            {
                InstalledApplicationPin.ProgramFilesParent => _safe,
                InstalledApplicationPin.InstalledRoot => _protectedParent,
                InstalledApplicationPin.ApplicationFile =>
                    ResolveProtectedEntry(
                        @"WireguardSplitTunnel\WireguardSplitTunnel.App.exe"),
                _ => throw new ArgumentOutOfRangeException(
                    nameof(pin),
                    pin,
                    "Unsupported installed application pin.")
            };

        public ProtectedAclNativeOpenResult OpenRoot(
            string rootPath,
            bool openReparsePoint,
            bool shareDelete,
            bool requireWriteAccess = false)
        {
            Requests.Add(new ProtectedAclNativeOpenRequest(
                ProtectedAclNativeObjectKind.Directory,
                ProtectedAclNativeDisposition.OpenExisting,
                openReparsePoint,
                shareDelete,
                SecurityDescriptor: null));
            return string.Equals(
                    rootPath,
                    @"C:\",
                    StringComparison.OrdinalIgnoreCase)
                ? ProtectedAclNativeOpenResult.Opened(
                    new FakeHandle(
                        _root,
                        Events,
                        shareDelete))
                : ProtectedAclNativeOpenResult.Failed(
                    ProtectedAclError.InvalidPath);
        }

        public ProtectedAclNativeOpenResult OpenRelative(
            IProtectedAclNativeHandle parent,
            string name,
            ProtectedAclNativeOpenRequest request)
        {
            Requests.Add(request);
            var fakeParent = (FakeHandle)parent;
            OpenedOutsidePinnedParent |=
                ReferenceEquals(fakeParent.Node, _outside);
            if (request.Disposition
                == ProtectedAclNativeDisposition.CreateNew)
            {
                SwapProtectedNamespace();
                CreatedParentIdentity =
                    fakeParent.Node.Snapshot.Identity;
                CreatedOutsidePinnedParent =
                    ReferenceEquals(fakeParent.Node, _outside);
                if (fakeParent.Node.Children.ContainsKey(name))
                {
                    return ProtectedAclNativeOpenResult.Failed(
                        ProtectedAclError.AlreadyExists);
                }

                var descriptor = request.SecurityDescriptor;
                if (descriptor is null)
                {
                    return ProtectedAclNativeOpenResult.Failed(
                        ProtectedAclError.SecurityMismatch);
                }

                var child = CreateNode(
                    Path.Combine(
                        fakeParent.Node.Snapshot.FinalPath,
                        name),
                    request.Kind
                        == ProtectedAclNativeObjectKind.Directory,
                    descriptor);
                fakeParent.Node.Children.Add(name, child);
                child.Parent = fakeParent.Node;
                child.Name = name;
                return ProtectedAclNativeOpenResult.Opened(
                    new FakeHandle(
                        child,
                        Events,
                        request.ShareDelete));
            }

            if (!fakeParent.Node.Children.TryGetValue(
                    name,
                    out var existing))
            {
                if (FailNextMissingOpenWithIo)
                {
                    FailNextMissingOpenWithIo = false;
                    return ProtectedAclNativeOpenResult.Failed(
                        ProtectedAclError.IoFailure);
                }

                return ProtectedAclNativeOpenResult.Failed(
                    ProtectedAclError.Missing);
            }

            if (existing.Snapshot.IsDirectory
                != (request.Kind
                    == ProtectedAclNativeObjectKind.Directory))
            {
                return ProtectedAclNativeOpenResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            return ProtectedAclNativeOpenResult.Opened(
                new FakeHandle(
                    existing,
                    Events,
                    request.ShareDelete));
        }


        public ProtectedAclNativeEnumerationResult EnumerateRelative(
            IProtectedAclNativeHandle directory)
        {
            Events.Add("enumerate");
            var node = ((FakeHandle)directory).Node;
            if (!node.Snapshot.IsDirectory || node.Deleted)
            {
                return ProtectedAclNativeEnumerationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            return ProtectedAclNativeEnumerationResult.Enumerated(
                node.Children
                    .OrderBy(pair => pair.Key, StringComparer.Ordinal)
                    .Select(pair =>
                        new ProtectedAclNativeDirectoryEntry(
                            pair.Key,
                            pair.Value.Snapshot.IsDirectory
                                ? ProtectedAclNativeObjectKind.Directory
                                : ProtectedAclNativeObjectKind.File,
                            pair.Value.Snapshot.IsReparsePoint))
                    .ToArray());
        }

        public ProtectedAclNativeOperationResult RenameRelative(
            IProtectedAclNativeHandle source,
            IProtectedAclNativeHandle destinationDirectory,
            string destinationName,
            bool replaceIfExists)
        {
            Events.Add("rename");
            var sourceNode = ((FakeHandle)source).Node;
            var destination = ((FakeHandle)destinationDirectory).Node;
            if (sourceNode.Deleted
                || sourceNode.Parent is null
                || !destination.Snapshot.IsDirectory)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.UnsafePath);
            }

            if (destination.Children.TryGetValue(
                    destinationName,
                    out var existing))
            {
                if (!replaceIfExists)
                {
                    return ProtectedAclNativeOperationResult.Failed(
                        ProtectedAclError.AlreadyExists);
                }

                existing.DeleteBackingFile();
                existing.Deleted = true;
                destination.Children.Remove(destinationName);
            }

            sourceNode.Parent.Children.Remove(sourceNode.Name);
            sourceNode.Parent = destination;
            sourceNode.Name = destinationName;
            sourceNode.SetFinalPath(
                Path.Combine(
                    destination.Snapshot.FinalPath,
                    destinationName));
            destination.Children.Add(destinationName, sourceNode);
            Events.Add("flush-directory");
            if (FailNextDirectoryFlush)
            {
                FailNextDirectoryFlush = false;
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.IoFailure,
                    namespaceChanged: true);
            }

            return ProtectedAclNativeOperationResult.Committed();
        }

        public ProtectedAclNativeOperationResult Delete(
            IProtectedAclNativeHandle target,
            bool directory)
        {
            Events.Add("delete");
            var node = ((FakeHandle)target).Node;
            if (node.Deleted
                || node.Snapshot.IsDirectory != directory
                || directory && node.Children.Count != 0)
            {
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.IoFailure);
            }

            node.Parent?.Children.Remove(node.Name);
            node.Deleted = true;
            node.DeleteBackingFile();
            return ProtectedAclNativeOperationResult.Committed();
        }

        public ProtectedAclNativeOperationResult FlushDirectory(
            IProtectedAclNativeHandle directory)
        {
            Events.Add("flush-directory");
            if (FailNextDirectoryFlush)
            {
                FailNextDirectoryFlush = false;
                return ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.IoFailure);
            }

            return ((FakeHandle)directory).Node.Snapshot.IsDirectory
                ? ProtectedAclNativeOperationResult.Committed(
                    namespaceChanged: false)
                : ProtectedAclNativeOperationResult.Failed(
                    ProtectedAclError.UnsafePath);
        }
        public void Dispose()
        {
            foreach (var path in _backingPaths)
            {
                try
                {
                    File.Delete(path);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }

        private FakeNode CreateNode(
            string finalPath,
            bool isDirectory,
            byte[] securityDescriptor)
        {
            string? backingPath = null;
            if (!isDirectory)
            {
                backingPath = Path.Combine(
                    Path.GetTempPath(),
                    $"protected-acl-fake-{Guid.NewGuid():N}.tmp");
                using (File.Create(backingPath))
                {
                }

                _backingPaths.Add(backingPath);
            }
            var identity = new ProtectedFileIdentity128(
                VolumeSerialNumber: 1,
                FileIdLow: _nextIdentity++,
                FileIdHigh: _nextIdentity++);
            return new FakeNode(new ProtectedAclNativeSnapshot(
                isDirectory,
                IsReparsePoint: false,
                finalPath,
                identity,
                securityDescriptor.ToArray()),
                backingPath);
        }

        private static byte[] InstalledDescendantDescriptor(
            bool directory)
        {
            var users = new SecurityIdentifier(
                WellKnownSidType.BuiltinUsersSid,
                null);
            var flags = directory
                ? AceFlags.ContainerInherit
                    | AceFlags.ObjectInherit
                    | AceFlags.Inherited
                : AceFlags.Inherited;
            var acl = new RawAcl(GenericAcl.AclRevision, 3);
            acl.InsertAce(
                0,
                new CommonAce(
                    flags,
                    AceQualifier.AccessAllowed,
                    (int)FileSystemRights.FullControl,
                    Administrators,
                    isCallback: false,
                    opaque: null));
            acl.InsertAce(
                1,
                new CommonAce(
                    flags,
                    AceQualifier.AccessAllowed,
                    (int)FileSystemRights.FullControl,
                    System,
                    isCallback: false,
                    opaque: null));
            acl.InsertAce(
                2,
                new CommonAce(
                    flags,
                    AceQualifier.AccessAllowed,
                    (int)(FileSystemRights.ReadAndExecute
                        | FileSystemRights.Synchronize),
                    users,
                    isCallback: false,
                    opaque: null));
            var raw = new RawSecurityDescriptor(
                ControlFlags.DiscretionaryAclPresent
                    | ControlFlags.SelfRelative,
                System,
                group: null,
                systemAcl: null,
                discretionaryAcl: acl);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            return bytes;
        }

        private sealed class FakeNode(
            ProtectedAclNativeSnapshot snapshot,
            string? backingPath)
        {
            public ProtectedAclNativeSnapshot Snapshot { get; private set; } =
                snapshot;
            public Dictionary<string, FakeNode> Children { get; } =
                new(StringComparer.OrdinalIgnoreCase);
            public FakeNode? Parent { get; set; }
            public string Name { get; set; } = string.Empty;
            public bool Deleted { get; set; }
            public int NoDeleteShareHandleCount { get; set; }

            public void SetFinalPath(string finalPath)
            {
                Snapshot = Snapshot with { FinalPath = finalPath };
                foreach (var child in Children.Values)
                {
                    child.SetFinalPath(
                        Path.Combine(finalPath, child.Name));
                }
            }

            public void WriteContent(byte[] bytes)
            {
                if (Snapshot.IsDirectory
                    || backingPath is null
                    || Deleted)
                {
                    throw new IOException("The fake node is not writable.");
                }

                File.WriteAllBytes(backingPath, bytes);
            }

            public byte[] ReadContent()
            {
                if (Snapshot.IsDirectory
                    || backingPath is null
                    || Deleted)
                {
                    throw new IOException("The fake node is not readable.");
                }

                return File.ReadAllBytes(backingPath);
            }

            public string GetBackingPath() =>
                !Snapshot.IsDirectory
                    && backingPath is not null
                    && !Deleted
                    ? backingPath
                    : throw new IOException(
                        "The fake node has no live backing file.");

            public void DeleteBackingFile()
            {
                if (backingPath is null)
                {
                    return;
                }

                try
                {
                    File.Delete(backingPath);
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }

        private sealed class FakeHandle
            : IProtectedAclNativeHandle
        {
            private bool _disposed;
            private readonly List<string> _events;
            private readonly bool _shareDelete;

            public FakeHandle(
                FakeNode node,
                List<string> events,
                bool shareDelete)
            {
                Node = node;
                _events = events;
                _shareDelete = shareDelete;
                if (!shareDelete)
                {
                    Node.NoDeleteShareHandleCount++;
                }
            }

            public FakeNode Node { get; }

            public ProtectedAclNativeSnapshot ReadSnapshot()
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (Node.Deleted)
                {
                    throw new FileNotFoundException(
                        Node.Snapshot.FinalPath);
                }

                return Node.Snapshot with
                {
                    SecurityDescriptor =
                        Node.Snapshot.SecurityDescriptor.ToArray()
                };
            }

            public FileStream TakeFileStream() =>
                OpenFileStream(FileAccess.ReadWrite);

            public FileStream OpenFileStream(FileAccess access)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (access == FileAccess.ReadWrite)
                {
                    _events.Add("open-write");
                    return new RecordingFileStream(
                        Node.GetBackingPath(),
                        _events);
                }

                _events.Add("open-read");
                return new FileStream(
                    Node.GetBackingPath(),
                    FileMode.Open,
                    access,
                    FileShare.ReadWrite | FileShare.Delete,
                    bufferSize: 4096,
                    FileOptions.None);
            }

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                if (!_shareDelete)
                {
                    Node.NoDeleteShareHandleCount--;
                }
                _events.Add($"dispose:{Node.Name}");
            }
        }

        private sealed class RecordingFileStream
            : FileStream
        {
            private readonly List<string> _events;

            public RecordingFileStream(
                string path,
                List<string> events)
                : base(
                    path,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.ReadWrite | FileShare.Delete,
                    bufferSize: 4096,
                    FileOptions.None)
            {
                _events = events;
            }

            public override void Flush(bool flushToDisk)
            {
                base.Flush(flushToDisk);
                _events.Add("flush-file");
            }
        }
    }

    private sealed class AclFixture : IDisposable
    {
        public AclFixture()
        {
            Root = Path.Combine(
                Path.GetTempPath(),
                "WireguardSplitTunnel.WindowsUpdate.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);
            Acl = new ProtectedDirectoryAcl();
        }

        public string Root { get; }
        public ProtectedDirectoryAcl Acl { get; }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Root))
                {
                    Directory.Delete(Root, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
