using ChomcioRecovery.Core;
using System.Security.Cryptography;

int assertions = 0;
int nativeLinkChecksExecuted = 0;
void Check(bool condition, string message)
{
    assertions++;
    if (!condition) throw new Exception("TEST FAILED: " + message);
}
void MustFail(Action action, string message)
{
    bool failed = false;
    try { action(); }
    catch (Exception e) when (e is IOException or InvalidDataException or ArgumentException or CryptographicException)
    {
        failed = true;
    }
    Check(failed, message);
}

void MustCancel(Action action, string message)
{
    bool cancelled = false;
    try { action(); }
    catch (OperationCanceledException) { cancelled = true; }
    Check(cancelled, message);
}

string sandbox = Path.Combine(Path.GetTempPath(), "chomcio-native-smoke-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(sandbox);
string fixtureStages=Path.Combine(sandbox,"identity-fixtures");Directory.CreateDirectory(fixtureStages);
try
{
    VolumePathScenarios.Run(sandbox, Check);
    if (args.SequenceEqual(new[]{"--volume-paths-only"}))
    {
        Console.WriteLine("CHOMCIO_VOLUME_ASSERTIONS="+assertions);
        return 0;
    }
    VaultProgressScenarios.Run(sandbox, Check);
    CancellationScenarios.Run(sandbox, Check);
    SystemLinkScenarios.Run(sandbox, Check);
    ZoneIdentifierScenarios.Run(sandbox, Check);
    // A failed verification must NEVER delete a stage by pathname. Stronger:
    // the ORIGINAL NtCreateFile root creator must deny same-user rename while
    // the native callback runs (before ACL verification and guard capture end).
    if (OperatingSystem.IsWindows())
    {
        string failedOriginalStage = "";
        bool failedRenameDenied = false;
        MustFail(() => PrivateRestoreStage.Create(fixtureStages, ".chomcio-acl-swap-smoke-",
            afterWindowsCreateBeforeValidation: createdPath =>
            {
                failedOriginalStage = createdPath;
                try { Directory.Move(createdPath, createdPath + ".stolen"); }
                catch (IOException) { failedRenameDenied = true; }
                throw new IOException("Native injected error after original-handle stage creation.");
            }), "failed original-handle stage create propagates without pathname deletion");
        Check(failedRenameDenied, "native root creator denies concurrent rename before return");
        Check(Directory.Exists(failedOriginalStage),
            "failure preserves original empty protected stage for review");
        Check(!Directory.Exists(failedOriginalStage + ".stolen"),
            "failure cannot relocate or adopt another stage name");

        bool liveRenameDenied = false;
        var rootOwned = PrivateRestoreStage.CreateOwned(fixtureStages,
            ".chomcio-root-pin-smoke-", afterWindowsCreateBeforeValidation: createdPath =>
            {
                try { Directory.Move(createdPath, createdPath + ".stolen"); }
                catch (IOException) { liveRenameDenied = true; }
            });
        using (rootOwned.Guard)
        {
            Check(liveRenameDenied, "original root FILE_CREATE rejects hostile rename");
            Check(Directory.Exists(rootOwned.Stage), "original protected root persists");
            Check(!Directory.Exists(rootOwned.Stage + ".stolen"),
                "no attacker-supplied root replaces original");
            rootOwned.Guard.RequireMatches(rootOwned.Stage);
        }
    }
    Console.WriteLine("CHOMCIO_NATIVE_FAILED_STAGE_NO_FOREIGN_DELETE=PASS");
    Console.WriteLine("CHOMCIO_NATIVE_HANDLE_BOUND_ROOT_STAGE=PASS");

    // 0.1.55: an initialized repository must be independently REOPENABLE
    // and match the exact salt/verifier bytes committed by this invocation.
    // A swapped, otherwise valid repository using the SAME password is also
    // a failure: it is NOT the key lineage Initialize() intended to create.
    const string initialPassword = "disposable-initialization-check-2026";
    string initialized = Path.Combine(sandbox, "init-verified-good");
    LocalEncryptedVault.Initialize(initialized, initialPassword);
    using (var independent = LocalEncryptedVault.Open(initialized, initialPassword))
        Check(independent.ListSnapshotIds().Count == 0,
            "freshly initialized repository is independently reopenable and empty");
    string userSentinel = Path.Combine(sandbox, "unrelated-existing-user-file.txt");
    File.WriteAllText(userSentinel, "keep user data untouched");
    for (int tamper = 0; tamper < 2; tamper++)
    {
        bool changedPublishedConfig = false;
        string candidate = Path.Combine(sandbox, "init-corrupt-" + tamper);
        MustFail(() => LocalEncryptedVault.InitializeCore(candidate, initialPassword,
            afterConfigPublished: publishedPath =>
            {
                using var original = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(publishedPath));
                string verifier = original.RootElement.GetProperty("Verifier").GetString()!;
                byte[] newSalt = RandomNumberGenerator.GetBytes(32);
                if (tamper == 1)
                {
                    byte[] replacementKey = Rfc2898DeriveBytes.Pbkdf2(initialPassword, newSalt,
                        310_000, HashAlgorithmName.SHA256, 32);
                    try
                    {
                        verifier = Convert.ToBase64String(HMACSHA256.HashData(
                            replacementKey, "ChomcioRecovery/key-check/v1"u8));
                    }
                    finally { CryptographicOperations.ZeroMemory(replacementKey); }
                }
                byte[] changed = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new
                {
                    Format = "chomcio-local-v1", Salt = Convert.ToBase64String(newSalt),
                    Iterations = 310_000, Verifier = verifier
                }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllBytes(publishedPath, changed);
                changedPublishedConfig = true;
                CryptographicOperations.ZeroMemory(newSalt);
            }), "a changed final repository config never reports initialization success");
        Check(changedPublishedConfig, "post-publication initialization fault was injected");
        Check(File.Exists(Path.Combine(candidate, "repo.json")),
            "unconfirmed initialized repository is not speculatively deleted");
    }
    Check(File.ReadAllText(userSentinel) == "keep user data untouched",
        "initialization rejection leaves unrelated user files intact");
    Console.WriteLine("CHOMCIO_NATIVE_INITIAL_REPOSITORY_READBACK=PASS");

    // An exception AFTER successful AES-GCM decryption must zero the exact
    // returned chunk buffer, not just AES-GCM failures. All fixtures are inside
    // this disposable native smoke sandbox; no user content is opened.
    string postDecryptSource = Path.Combine(sandbox, "post-decrypt-clear-source");
    Directory.CreateDirectory(postDecryptSource);
    byte[] postDecryptExpected = RandomNumberGenerator.GetBytes(4097);
    File.WriteAllBytes(Path.Combine(postDecryptSource, "payload.bin"), postDecryptExpected);
    using (var hygieneVault = LocalEncryptedVault.Open(initialized, initialPassword))
    {
        var hygieneBackup = hygieneVault.BackupDirectory(postDecryptSource);
        string hygieneChunk = hygieneVault.ReadSnapshot(hygieneBackup.SnapshotId)
            .Files.Single().Chunks.Single();
        byte[]? thrownPlaintext = null;
        bool unexpectedFault = false;
        try
        {
            hygieneVault.ReadChunkAndValidateForSmoke(hygieneChunk, CancellationToken.None,
                afterDecryption: buffer =>
                {
                    Check(buffer.AsSpan().SequenceEqual(postDecryptExpected),
                        "fault hook receives genuine AES-GCM-decrypted bytes");
                    thrownPlaintext = buffer;
                    throw new IOException("Native deliberate post-decryption failure.");
                });
        }
        catch (IOException) { unexpectedFault = true; }
        Check(unexpectedFault && thrownPlaintext is not null,
            "injected post-AES-GCM exception propagates");
        Check(thrownPlaintext is not null && thrownPlaintext.All(b => b == 0),
            "post-decrypt failure clears the EXACT escaped plaintext buffer");

        byte[]? canceledPlaintext = null;
        using var decryptedCancel = new CancellationTokenSource();
        MustCancel(() => hygieneVault.ReadChunkAndValidateForSmoke(hygieneChunk, decryptedCancel.Token,
            afterDecryption: buffer =>
            {
                Check(buffer.AsSpan().SequenceEqual(postDecryptExpected),
                    "post-decrypt cancellation runs on genuine plaintext");
                canceledPlaintext = buffer;
                decryptedCancel.Cancel();
            }), "cancellation after AES-GCM authentication never returns plaintext");
        Check(canceledPlaintext is not null && canceledPlaintext.All(b => b == 0),
            "post-decrypt cancellation clears original plaintext buffer");

        byte[] authenticated = hygieneVault.ReadChunkAndValidateForSmoke(hygieneChunk, CancellationToken.None, _ => { });
        try { Check(authenticated.AsSpan().SequenceEqual(postDecryptExpected),
            "normal authenticated chunk still returns exact plaintext"); }
        finally { CryptographicOperations.ZeroMemory(authenticated); }
    }
    CryptographicOperations.ZeroMemory(postDecryptExpected);
    Console.WriteLine("CHOMCIO_NATIVE_POST_DECRYPT_FAILURE_ZEROIZATION=PASS");


    // 0.1.42: Write-through + Flush is not independent verification of the
    // encrypted bytes on disk. Inject a corrupted or shortened TEMP record
    // immediately before its fresh-handle readback; neither may be published.
    string atomicGood = Path.Combine(sandbox, "atomic-good.obj");
    byte[] atomicContent = RandomNumberGenerator.GetBytes(65_537);
    LocalEncryptedVault.WriteAtomic(atomicGood, atomicContent);
    Check(File.ReadAllBytes(atomicGood).SequenceEqual(atomicContent),
        "atomic record preserves bytes after verified publication");
    string atomicBad = Path.Combine(sandbox, "atomic-bad.obj");
    MustFail(() => LocalEncryptedVault.WriteAtomic(atomicBad, atomicContent,
        beforeReadback: temp =>
        {
            using var corrupted = new FileStream(temp, FileMode.Open, FileAccess.Write, FileShare.None);
            corrupted.Position = 200;
            corrupted.WriteByte((byte)(atomicContent[200] ^ 0x01));
            corrupted.Flush(flushToDisk: true);
        }), "atomic record corrupt stage never becomes a committed record");
    Check(!File.Exists(atomicBad), "atomic bad record must not be published");
    Check(!Directory.EnumerateFiles(sandbox, "atomic-bad.obj.tmp-*").Any(),
        "failed atomic record temporary file is cleaned");
    string atomicTruncated = Path.Combine(sandbox, "atomic-short.obj");
    MustFail(() => LocalEncryptedVault.WriteAtomic(atomicTruncated, atomicContent,
        beforeReadback: temp =>
        {
            using var truncated = new FileStream(temp, FileMode.Truncate, FileAccess.Write, FileShare.None);
            truncated.Flush(flushToDisk: true);
        }), "atomic record truncated stage never becomes a committed record");
    Check(!File.Exists(atomicTruncated), "shortened record must not be published");
    Check(!Directory.EnumerateFiles(sandbox, "atomic-short.obj.tmp-*").Any(),
        "shortened atomic temporary file is cleaned");
    Console.WriteLine("CHOMCIO_NATIVE_ATOMIC_RECORD_READBACK=PASS");
    // A source pathname race AFTER full temp verification used to let the
    // subsequent File.Move publish a different file. The owned DELETE handle
    // must deny source rename until the kernel itself publishes THAT handle.
    // The same no-replace operation must preserve an existing final name.
    if (OperatingSystem.IsWindows())
    {
        string pinnedTarget = Path.Combine(sandbox, "record-owned-rename.obj");
        bool attemptedRenameDenied = false;
        LocalEncryptedVault.WriteAtomic(pinnedTarget, atomicContent,
            whileOwnedHandlePinned: temp =>
            {
                try { File.Move(temp, temp + ".alien"); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    attemptedRenameDenied = true;
                }
            });
        Check(attemptedRenameDenied, "owned Windows record handle denies late temp rename");
        Check(File.ReadAllBytes(pinnedTarget).SequenceEqual(atomicContent),
            "handle-owned rename publishes original verified bytes");
        string collisionTarget = Path.Combine(sandbox, "record-owned-collision.obj");
        byte[] protectedExisting = "existing data must survive"u8.ToArray();
        bool collisionInjected = false;
        MustFail(() => LocalEncryptedVault.WriteAtomic(collisionTarget, atomicContent,
            whileOwnedHandlePinned: _ =>
            {
                File.WriteAllBytes(collisionTarget, protectedExisting);
                collisionInjected = true;
            }), "owned Windows record no-replace rename rejects a late destination collision");
        Check(collisionInjected && File.ReadAllBytes(collisionTarget).SequenceEqual(protectedExisting),
            "late destination collision must preserve unrelated existing bytes");
        Check(!Directory.EnumerateFiles(sandbox, "record-owned-collision.obj.tmp-*").Any(),
            "failed owned rename cleans only the original temporary file");
        using var stopPublish = new CancellationTokenSource();
        string cancelledTarget = Path.Combine(sandbox, "record-owned-cancel.obj");
        MustCancel(() => LocalEncryptedVault.WriteAtomic(cancelledTarget, atomicContent,
            cancellationToken: stopPublish.Token,
            whileOwnedHandlePinned: _ => stopPublish.Cancel()),
            "cancel during retained-handle revalidation prevents publication");
        Check(!File.Exists(cancelledTarget),
            "cancelled owned-handle publication must not create a final record");
        Check(!Directory.EnumerateFiles(sandbox, "record-owned-cancel.obj.tmp-*").Any(),
            "cancelled owned-handle publication only cleans its own stage");

        // The verified FILE_OBJECT alone cannot guarantee its PARENT directory
        // still has the expected pathname. Attempt a live directory rename
        // inside the actual publication callback, with an isolated synthetic
        // directory. On NTFS it MUST fail until publication completes.
        string ancestorParent = Path.Combine(sandbox, "record-ancestor-own");
        Directory.CreateDirectory(ancestorParent);
        string ancestorTarget = Path.Combine(ancestorParent, "record.bin");
        bool ancestorRenameDenied = false;
        LocalEncryptedVault.WriteAtomic(ancestorTarget, atomicContent,
            whileOwnedHandlePinned: _ =>
            {
                try { Directory.Move(ancestorParent, ancestorParent + ".alien"); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    ancestorRenameDenied = true;
                }
            });
        Check(ancestorRenameDenied, "pinned ciphertext parent must deny late directory rename");
        Check(File.ReadAllBytes(ancestorTarget).SequenceEqual(atomicContent),
            "parent-pinned publication must preserve exact ciphertext bytes");
        Check(!Directory.Exists(ancestorParent + ".alien"),
            "record parent was never redirected during the native publication");
        Console.WriteLine("CHOMCIO_NATIVE_RECORD_PARENT_PIN=PASS");

        // Regression: the previous cleanup used FileId pathname check followed
        // by File.Delete(path), leaving a last-step name replacement race.
        // A DELETE-capable no-share-delete handle must own the SAME staged
        // file throughout cleanup. Only disposable synthetic test files.
        string cleanupPath = Path.Combine(sandbox, "record-cleanup-owned.tmp");
        File.WriteAllBytes(cleanupPath, atomicContent);
        var cleanupIdentity = WindowsSourceFileIdentity.CaptureFile(cleanupPath);
        bool cleanupRenameDenied = false;
        WindowsRecordStageGuard.CleanupOnlyOriginalTemp(cleanupPath, cleanupIdentity,
            whilePinned: stage =>
            {
                try { File.Move(stage, stage + ".stolen"); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    cleanupRenameDenied = true;
                }
            });
        Check(cleanupRenameDenied, "original cleanup handle denies concurrent stage rename");
        Check(!File.Exists(cleanupPath) && !File.Exists(cleanupPath + ".stolen"),
            "original cleanup handle deleted only its own verified temp");

        string changedTemp = Path.Combine(sandbox, "record-cleanup-foreign.tmp");
        string originalElsewhere = Path.Combine(sandbox, "record-cleanup-original-preserved.bin");
        File.WriteAllBytes(changedTemp, atomicContent);
        var originalCleanupId = WindowsSourceFileIdentity.CaptureFile(changedTemp);
        File.Move(changedTemp, originalElsewhere);
        byte[] foreignCleanupBytes = "foreign user file must survive failed cleanup"u8.ToArray();
        File.WriteAllBytes(changedTemp, foreignCleanupBytes);
        MustFail(() => WindowsRecordStageGuard.CleanupOnlyOriginalTemp(changedTemp, originalCleanupId),
            "a replaced temporary cleanup pathname cannot delete a foreign file");
        Check(File.ReadAllBytes(changedTemp).SequenceEqual(foreignCleanupBytes),
            "foreign record survives failed handle-bound cleanup unchanged");
        Check(File.ReadAllBytes(originalElsewhere).SequenceEqual(atomicContent),
            "moved original encrypted temp survives identity mismatch");

        // Even direct cleanup callers must retain the REAL ancestor namespace;
        // the verified DELETE handle alone cannot pin the parent pathname.
        string cleanupAncestor = Path.Combine(sandbox, "record-cleanup-ancestor-own");
        Directory.CreateDirectory(cleanupAncestor);
        string cleanupAncestorStage = Path.Combine(cleanupAncestor, "stage.tmp");
        File.WriteAllBytes(cleanupAncestorStage, atomicContent);
        var cleanupAncestorId = WindowsSourceFileIdentity.CaptureFile(cleanupAncestorStage);
        bool cleanupAncestorRenameDenied = false;
        WindowsRecordStageGuard.CleanupOnlyOriginalTemp(cleanupAncestorStage, cleanupAncestorId,
            whilePinned: _ =>
            {
                try { Directory.Move(cleanupAncestor, cleanupAncestor + ".alien"); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    cleanupAncestorRenameDenied = true;
                }
            });
        Check(cleanupAncestorRenameDenied, "record temp cleanup denies parent retarget");
        Check(!File.Exists(cleanupAncestorStage) && Directory.Exists(cleanupAncestor),
            "ancestor pin cleanup removed its verified stage without moving its parent");
        Check(!Directory.Exists(cleanupAncestor + ".alien"),
            "foreign cleanup parent rename never committed");
        Console.WriteLine("CHOMCIO_NATIVE_HANDLE_BOUND_TEMP_CLEANUP=PASS");
        Console.WriteLine("CHOMCIO_NATIVE_HANDLE_BOUND_RECORD_PUBLISH=PASS");

        // Critical creator-identity regression: a pathname capture AFTER the
        // original writer closes could bind to a substitute with identical
        // ciphertext, even though both subsequent readbacks pass. The new
        // hook is deliberately before the old post-close capture boundary.
        string creatorTarget = Path.Combine(sandbox, "record-creator-id.obj");
        string creatorRelocated = Path.Combine(sandbox, "record-creator-original.bin");
        string? creatorForeignTemp = null;
        bool attemptedEarlySwap = false;
        MustFail(() => LocalEncryptedVault.WriteAtomic(creatorTarget, atomicContent,
            afterOriginalWriterClosed: temp =>
            {
                File.Move(temp, creatorRelocated);
                File.WriteAllBytes(temp, atomicContent); // exact same ciphertext
                creatorForeignTemp = temp;
                attemptedEarlySwap = true;
            }), "post-writer-close, pre-path-capture foreign ciphertext must not be adopted");
        Check(attemptedEarlySwap && creatorForeignTemp is not null,
            "creator-bound test actually performed the early pathname swap");
        Check(!File.Exists(creatorTarget), "foreign creator-stage bytes never published");
        Check(File.ReadAllBytes(creatorForeignTemp!).SequenceEqual(atomicContent),
            "swapped same-byte foreign temp is never deleted");
        Check(File.ReadAllBytes(creatorRelocated).SequenceEqual(atomicContent),
            "moved original writer FILE_OBJECT survives the failed commit");
        Console.WriteLine("CHOMCIO_NATIVE_WRITER_BOUND_TEMP_IDENTITY=PASS");
    }
    // 0.1.56: an attacker can replace the randomized temp PATH after the
    // write/flush but BEFORE the opened-handle readback. With byte-identical
    // contents, byte comparison alone would falsely authorize publishing the
    // unrelated file. Error cleanup must not delete that foreign file either.
    foreach (bool identicalBytes in new[] { true, false })
    {
        string tag = identicalBytes ? "same" : "other";
        string target = Path.Combine(sandbox, "atomic-swap-" + tag + ".obj");
        string relocatedStage = Path.Combine(sandbox, "atomic-owned-" + tag + ".bin");
        string? foreignTemp = null;
        byte[] replacement = identicalBytes ? atomicContent : "keep alien user bytes"u8.ToArray();
        MustFail(() => LocalEncryptedVault.WriteAtomic(target, atomicContent,
            beforeReadback: temp =>
            {
                File.Move(temp, relocatedStage);
                File.WriteAllBytes(temp, replacement);
                foreignTemp = temp;
            }), "foreign immutable-record temporary pathname must refuse publication");
        Check(foreignTemp is not null && File.Exists(foreignTemp),
            "unrelated replacement file must never be deleted during failed commit cleanup");
        Check(File.ReadAllBytes(foreignTemp!).SequenceEqual(replacement),
            "foreign file contents remain unmodified");
        Check(File.ReadAllBytes(relocatedStage).SequenceEqual(atomicContent),
            "original owned stage is preserved separately");
        Check(!File.Exists(target),
            "record cannot publish a different temp inode even with identical contents");
    }
    Console.WriteLine("CHOMCIO_NATIVE_ATOMIC_TEMP_IDENTITY=PASS");

    // 0.1.47: a verified temporary record can still become corrupted after
    // its final rename. Final-path readback must refuse to report success.
    string publishedGood = Path.Combine(sandbox, "published-good.snap");
    LocalEncryptedVault.WriteAtomicAndVerifyPublished(publishedGood, atomicContent);
    Check(File.ReadAllBytes(publishedGood).SequenceEqual(atomicContent),
        "unchanged final snapshot bytes pass independent readback");
    string publishedBad = Path.Combine(sandbox, "published-bad.snap");
    bool afterPublicationReached = false;
    MustFail(() => LocalEncryptedVault.WriteAtomicAndVerifyPublished(publishedBad, atomicContent,
        afterPublished: publishedPath =>
        {
            using var changed = new FileStream(publishedPath, FileMode.Open,
                FileAccess.ReadWrite, FileShare.None);
            changed.Position = 70;
            int oldByte = changed.ReadByte();
            changed.Position = 70;
            changed.WriteByte((byte)(oldByte ^ 0x01));
            changed.Flush(flushToDisk: true);
            afterPublicationReached = true;
        }), "post-rename corruption of the published record refuses success");
    Check(afterPublicationReached, "final-path readback fault injection executed");
    Check(File.Exists(publishedBad) && !File.ReadAllBytes(publishedBad).SequenceEqual(atomicContent),
        "published corruption is detected without blindly deleting an existing name");
    Console.WriteLine("CHOMCIO_NATIVE_PUBLISHED_RECORD_READBACK=PASS");

    // Creator-bound final readback: post-rename contents are not enough.
    // Move our original published record away, then substitute an unrelated
    // file with exactly the SAME bytes. A path-only SHA falsely passes.
    string finalSwapName = Path.Combine(sandbox, "published-foreign-same.snap");
    string movedPublishedOriginal = Path.Combine(sandbox, "published-creator-original.bin");
    bool finalSwapInjected = false;
    MustFail(() => LocalEncryptedVault.WriteAtomicAndVerifyPublished(finalSwapName, atomicContent,
        afterPublished: publishedPath =>
        {
            File.Move(publishedPath, movedPublishedOriginal);
            File.WriteAllBytes(publishedPath, atomicContent);
            finalSwapInjected = true;
        }), "byte-identical foreign published FILE_OBJECT cannot confirm a successful backup");
    Check(finalSwapInjected && File.Exists(finalSwapName) && File.Exists(movedPublishedOriginal),
        "post-rename foreign replacement and original both remain for review");
    Check(File.ReadAllBytes(finalSwapName).SequenceEqual(atomicContent) &&
          File.ReadAllBytes(movedPublishedOriginal).SequenceEqual(atomicContent),
        "never modify or delete either a byte-identical foreign name or moved original");
    Console.WriteLine("CHOMCIO_NATIVE_CREATOR_BOUND_FINAL_READBACK=PASS");

    // 0.1.56: STOP *after* the no-replace rename previously went unnoticed
    // throughout the 64KiB-block FINAL record readback. The operation must
    // throw cancellation, NOT claim a successful backup. This is a synthetic
    // isolated path and a fully committed final record MUST be preserved;
    // cancellation is NOT rollback after publication.
    using (var stopAfterPublish = new CancellationTokenSource())
    {
        string finalName = Path.Combine(sandbox, "published-stop-after-commit.snap");
        bool finalCallbackReached = false;
        byte[] largePublishedRecord = RandomNumberGenerator.GetBytes(3 * 65_536 + 19);
        MustCancel(() => LocalEncryptedVault.WriteAtomicAndVerifyPublished(
            finalName, largePublishedRecord,
            afterPublished: _ =>
            {
                finalCallbackReached = true;
                stopAfterPublish.Cancel();
            }, cancellationToken: stopAfterPublish.Token),
            "STOP after record rename must reject false completion");
        Check(finalCallbackReached, "post-commit cancellation injection executed");
        Check(File.Exists(finalName) && File.ReadAllBytes(finalName).SequenceEqual(largePublishedRecord),
            "cancel after irreversible publish preserves committed original; no unsafe name deletion");
    }
    Console.WriteLine("CHOMCIO_NATIVE_POST_COMMIT_CANCELLATION=PASS");

    // Post-publication STOP must ALSO reach the final potentially multi-GB
    // full-tree restore, one-file restore and portable encrypted export audit.
    // All three publish a visible path BEFORE this cancellation boundary:
    // cancellation must propagate, but MUST NOT delete the committed result.
    const string postVisibilityPassword = "disposable-post-visibility-stop-2026";
    string postVisibilityVault = Path.Combine(sandbox, "post-visibility-vault");
    string postVisibilityInput = Path.Combine(sandbox, "post-visibility-input");
    Directory.CreateDirectory(postVisibilityInput);
    byte[] postVisibilityPlain = RandomNumberGenerator.GetBytes(2 * LocalEncryptedVault.ChunkBytes + 17);
    string postVisibilityName = "unicode-zażółć.bin";
    File.WriteAllBytes(Path.Combine(postVisibilityInput, postVisibilityName), postVisibilityPlain);
    LocalEncryptedVault.Initialize(postVisibilityVault, postVisibilityPassword);
    using (var postVisibility = LocalEncryptedVault.Open(postVisibilityVault, postVisibilityPassword))
    {
        string postVisibilityId = postVisibility.BackupDirectory(postVisibilityInput).SnapshotId;
        using (var treeStop = new CancellationTokenSource())
        {
            string visibleTree = Path.Combine(sandbox, "post-visible-restore-tree");
            bool publishedTreeCallback = false;
            MustCancel(() => postVisibility.RestoreSnapshotCore(postVisibilityId, visibleTree,
                beforeStageReadback: null,
                afterPublished: result =>
                {
                    publishedTreeCallback = true;
                    Check(Directory.Exists(result), "tree name is visible when STOP arrives");
                    treeStop.Cancel();
                }, cancellationToken: treeStop.Token),
                "post-publication tree restore STOP must interrupt final SHA readback");
            Check(publishedTreeCallback && Directory.Exists(visibleTree),
                "post-commit tree STOP preserves the original published destination");
            Check(File.ReadAllBytes(Path.Combine(visibleTree, postVisibilityName)).SequenceEqual(postVisibilityPlain),
                "post-commit tree STOP preserves exact original plaintext bytes");
        }
        using (var fileStop = new CancellationTokenSource())
        {
            string visibleFile = Path.Combine(sandbox, "post-visible-restore-file.bin");
            bool publishedFileCallback = false;
            MustCancel(() => postVisibility.RestoreFileCore(postVisibilityId, postVisibilityName,
                visibleFile, beforeStageReadback: null,
                afterPublished: result =>
                {
                    publishedFileCallback = true;
                    Check(File.Exists(result), "file name is visible when STOP arrives");
                    fileStop.Cancel();
                }, cancellationToken: fileStop.Token),
                "post-publication file restore STOP must interrupt final SHA readback");
            Check(publishedFileCallback && File.ReadAllBytes(visibleFile).SequenceEqual(postVisibilityPlain),
                "post-commit file STOP preserves byte-exact published original");
        }
        using (var exportStop = new CancellationTokenSource())
        {
            string visibleExport = Path.Combine(sandbox, "post-visible-portable-export");
            bool publishedExportCallback = false;
            MustCancel(() => postVisibility.ExportEncryptedSnapshotCore(postVisibilityId, visibleExport,
                afterPublished: result =>
                {
                    publishedExportCallback = true;
                    Check(Directory.Exists(result), "portable export is visible when STOP arrives");
                    exportStop.Cancel();
                }, cancellationToken: exportStop.Token),
                "post-publication encrypted export STOP must interrupt final authenticated audit");
            Check(publishedExportCallback && Directory.Exists(visibleExport),
                "post-commit export STOP preserves original encrypted repository");
            using var reopenedVisible = LocalEncryptedVault.Open(visibleExport, postVisibilityPassword);
            reopenedVisible.VerifySnapshot(postVisibilityId); // independent reconciled export succeeds
        }
        postVisibility.VerifySnapshot(postVisibilityId); // original remains independently valid
    }
    Console.WriteLine("CHOMCIO_NATIVE_POST_PUBLICATION_RESTORE_EXPORT_CANCEL=PASS");



    // 0.1.49: the published snapshot name can be correct while a referenced
    // object is corrupted between PRE-commit verification and publication.
    // Use an isolated disposable vault so the corruption fixture never affects
    // the normal smoke backup or its later restore tests.
    string dependencyRoot = Path.Combine(sandbox, "published-dependencies-vault");
    string dependencyInput = Path.Combine(sandbox, "published-dependencies-input");
    Directory.CreateDirectory(dependencyInput);
    File.WriteAllBytes(Path.Combine(dependencyInput, "fixture.dat"),
        "independent final snapshot object verification"u8.ToArray());
    const string dependencyPassword = "synthetic-dependencies-password-2026";
    LocalEncryptedVault.Initialize(dependencyRoot, dependencyPassword);
    using (var auditVault = LocalEncryptedVault.Open(dependencyRoot, dependencyPassword))
    {
        var originalPoint = auditVault.BackupDirectory(dependencyInput);
        var originalManifest = auditVault.ReadSnapshot(originalPoint.SnapshotId);
        // Backup-level cancellation must propagate through the final dependency
        // check as well as the direct record-readback code. Exercise the real
        // native fault hook after publication with valid existing chunks.
        using (var backupStop = new CancellationTokenSource())
        {
            string interruptedId = Guid.NewGuid().ToString("N");
            bool stoppedAtPublication = false;
            MustCancel(() => auditVault.PublishVerifiedSnapshot(interruptedId, originalManifest,
                preCommitCheck: () => { },
                afterPublished: _ =>
                {
                    stoppedAtPublication = true;
                    backupStop.Cancel();
                }, cancellationToken: backupStop.Token),
                "backup STOP after publication must not report normal completion");
            Check(stoppedAtPublication, "backup post-publication STOP was actually injected");
            auditVault.VerifySnapshot(interruptedId); // published content was not destructively rolled back
            Check(File.Exists(Path.Combine(dependencyRoot, "snapshots", interruptedId + ".snap")),
                "cancelled-but-published snapshot retained safely for explicit inspection");
        }

        // The live source may be rewritten AFTER the snapshot manifest was
        // committed and while the complete encrypted dependency audit runs.
        // Bytes and object IDs then remain authentic for the OLD content, but
        // backup success would be a false statement about the live source.
        // This native disposable-vault fixture changes the SAME source file
        // in place (same length, restored last-write timestamp), not user data.
        string sourceLeaf = Path.Combine(dependencyInput, "fixture.dat");
        byte[] sourceOriginal = File.ReadAllBytes(sourceLeaf);
        DateTime sourceOriginalWriteUtc = File.GetLastWriteTimeUtc(sourceLeaf);
        var sourceInitial = LocalEncryptedVault.CaptureSourceInventory(dependencyInput);
        int attestationCalls = 0;
        bool changedAfterCommit = false;
        string changedSourcePoint = Guid.NewGuid().ToString("N");
        try
        {
            MustFail(() => auditVault.PublishVerifiedSnapshot(changedSourcePoint,
                originalManifest,
                preCommitCheck: () =>
                {
                    attestationCalls++;
                    LocalEncryptedVault.VerifySourceContents(dependencyInput,
                        originalManifest.Files, sourceInitial);
                },
                afterPublished: _ =>
                {
                    byte[] changed = (byte[])sourceOriginal.Clone();
                    changed[0] ^= 0x59;
                    using (var editor = new FileStream(sourceLeaf, FileMode.Open,
                               FileAccess.Write, FileShare.ReadWrite))
                    {
                        editor.Write(changed);
                        editor.Flush(flushToDisk: true);
                    }
                    File.SetLastWriteTimeUtc(sourceLeaf, sourceOriginalWriteUtc);
                    changedAfterCommit = true;
                }),
                "source changed after commit must reject backup success despite authenticated ciphertext");
            Check(changedAfterCommit && attestationCalls == 2,
                "post-commit source SHA attestation ran AFTER encrypted dependency verification");
            Check(File.ReadAllBytes(sourceLeaf)[0] != sourceOriginal[0],
                "in-place source mutation was genuine and preserved the source FileObject");
            string committedSourcePoint = Path.Combine(dependencyRoot, "snapshots",
                changedSourcePoint + ".snap");
            Check(File.Exists(committedSourcePoint),
                "unconfirmed post-commit recovery point is preserved, not speculatively deleted");
            auditVault.VerifySnapshot(changedSourcePoint);
            // It is a genuine encrypted, restorable checkpoint of the OLD
            // bytes; unsuccessful backup must not claim source consistency.
        }
        finally
        {
            File.WriteAllBytes(sourceLeaf, sourceOriginal);
            File.SetLastWriteTimeUtc(sourceLeaf, sourceOriginalWriteUtc);
        }
        Console.WriteLine("CHOMCIO_NATIVE_POST_COMMIT_SOURCE_ATTESTATION=PASS");

        string objectId = originalManifest.Files[0].Chunks[0];
        string objectPath = Path.Combine(dependencyRoot, "objects", objectId[..2], objectId + ".obj");
        byte[] intactCiphertext = File.ReadAllBytes(objectPath);
        bool injected = false;
        string unconfirmedId = Guid.NewGuid().ToString("N");
        try
        {
            MustFail(() => auditVault.PublishVerifiedSnapshot(unconfirmedId,
                originalManifest, () => {}, afterPublished: publishedPath =>
                {
                    byte[] damaged = (byte[])intactCiphertext.Clone();
                    damaged[^1] ^= 0x37;
                    File.WriteAllBytes(objectPath, damaged);
                    injected = true;
                }), "post-commit corrupted dependency must reject backup success");
            Check(injected, "post-publication dependency mutation was actually injected");
            Check(File.Exists(Path.Combine(dependencyRoot, "snapshots", unconfirmedId + ".snap")),
                "unconfirmed committed snapshot name is not speculatively deleted");
        }
        finally
        {
            File.WriteAllBytes(objectPath, intactCiphertext);
        }
        auditVault.VerifySnapshot(originalPoint.SnapshotId);
    }
    Console.WriteLine("CHOMCIO_NATIVE_PUBLISHED_DEPENDENCIES=PASS");

    // 0.1.51: Stage verification alone is insufficient for offline export.
    // Inject corruption AFTER the final encrypted vault directory is renamed,
    // when the exported object/config is already visible to the user.
    string exportReadbackInput = Path.Combine(sandbox, "export-readback-input");
    string exportReadbackRoot = Path.Combine(sandbox, "export-readback-vault");
    Directory.CreateDirectory(exportReadbackInput);
    File.WriteAllBytes(Path.Combine(exportReadbackInput, "recoverable.bin"),
        "published export native fixture"u8.ToArray());
    const string exportReadbackPassword = "synthetic-export-readback-2026-password";
    LocalEncryptedVault.Initialize(exportReadbackRoot, exportReadbackPassword);
    using (var auditExport = LocalEncryptedVault.Open(exportReadbackRoot, exportReadbackPassword))
    {
        string auditedPoint = auditExport.BackupDirectory(exportReadbackInput).SnapshotId;
        string goodPortable = Path.Combine(sandbox, "export-readback-good");
        bool privateExportStageChecked = false;
        auditExport.ExportEncryptedSnapshotCore(auditedPoint, goodPortable, afterPublished: null,
            beforePublication: stage =>
            {
                Check(Path.GetFileName(stage).StartsWith(".chomcio-export-", StringComparison.Ordinal),
                    "portable export uses isolated private stage");
                if (OperatingSystem.IsWindows())
                    PrivateRestoreStage.AssertWindowsProtectedDacl(stage);
                else
                {
                    UnixFileMode other = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                        UnixFileMode.GroupExecute | UnixFileMode.OtherRead |
                        UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
                    Check((File.GetUnixFileMode(stage) & other) == 0,
                        "portable export stage is not public on Unix");
                    foreach (string directory in Directory.EnumerateDirectories(stage, "*", SearchOption.AllDirectories))
                        Check((File.GetUnixFileMode(directory) & other) == 0,
                            "portable export child directory is not public on Unix");
                    foreach (string file in Directory.EnumerateFiles(stage, "*", SearchOption.AllDirectories))
                        Check((File.GetUnixFileMode(file) & other) == 0,
                            "portable export record is not public on Unix");
                }
                privateExportStageChecked = true;
            });
        Check(privateExportStageChecked, "native private export staging callback executed");
        Console.WriteLine("CHOMCIO_NATIVE_PRIVATE_PORTABLE_EXPORT_STAGE=PASS");
        // Native Windows adversarial cleanup: an interrupted PORTABLE encrypted
        // export previously retained an entire nonempty private stage because
        // deleting by recursive pathname could erase a swapped foreign tree.
        // These checks require actual NtCreateFile/NTFS identity behavior.
        if (OperatingSystem.IsWindows())
        {
            string interruptedTarget = Path.Combine(sandbox, "export-owned-interrupted");
            string? interruptedStage = null;
            MustFail(() => auditExport.ExportEncryptedSnapshotCore(auditedPoint,
                interruptedTarget, afterPublished: null, beforePublication: staged =>
                {
                    interruptedStage = staged;
                    throw new IOException("Synthetic pre-commit portable export failure.");
                }), "interrupted portable export must not be published");
            Check(interruptedStage is not null && !Directory.Exists(interruptedStage) &&
                !Directory.Exists(interruptedTarget),
                "owned encrypted export must clean verified ORIGINAL records and empty stage");

            string substitutedTarget = Path.Combine(sandbox, "export-owned-swapped");
            string savedOriginal = Path.Combine(sandbox, "export-owned-original-preserved.obj");
            string? substitutedStage = null;
            string? substitutedFile = null;
            byte[] foreign = "foreign-export-record-must-survive"u8.ToArray();
            MustFail(() => auditExport.ExportEncryptedSnapshotCore(auditedPoint,
                substitutedTarget, afterPublished: null, beforePublication: staged =>
                {
                    substitutedStage = staged;
                    string oldRecord = Directory.EnumerateFiles(Path.Combine(staged, "objects"),
                        "*.obj", SearchOption.AllDirectories).Single();
                    // Move the original verified object OUTSIDE the private stage,
                    // then substitute an unrelated file at precisely its old name.
                    File.Move(oldRecord, savedOriginal);
                    File.WriteAllBytes(oldRecord, foreign);
                    substitutedFile = oldRecord;
                    throw new IOException("Synthetic foreign record insertion.");
                }), "foreign object swap must abort portable export");
            Check(substitutedStage is not null && Directory.Exists(substitutedStage) &&
                substitutedFile is not null && File.Exists(substitutedFile) &&
                File.ReadAllBytes(substitutedFile).AsSpan().SequenceEqual(foreign) &&
                File.Exists(savedOriginal) && !Directory.Exists(substitutedTarget),
                "cleanup MUST retain foreign record and ORIGINAL exported object after swap");
            Console.WriteLine("CHOMCIO_NATIVE_OWNED_PORTABLE_EXPORT_CLEANUP=PASS");
        }

        using (var independentlyOpened = LocalEncryptedVault.Open(goodPortable, exportReadbackPassword))
            independentlyOpened.VerifySnapshot(auditedPoint);

        string corruptedPortable = Path.Combine(sandbox, "export-readback-corrupted-object");
        bool mutatedExportObject = false;
        MustFail(() => auditExport.ExportEncryptedSnapshotCore(auditedPoint, corruptedPortable,
            afterPublished: destination =>
            {
                string objectFile = Directory.EnumerateFiles(Path.Combine(destination, "objects"),
                    "*.obj", SearchOption.AllDirectories).Single();
                using var changed = new FileStream(objectFile, FileMode.Open,
                    FileAccess.ReadWrite, FileShare.None);
                changed.Position = changed.Length - 1;
                int previous = changed.ReadByte();
                changed.Position = changed.Length - 1;
                changed.WriteByte((byte)(previous ^ 0x08));
                changed.Flush(flushToDisk: true);
                mutatedExportObject = true;
            }), "export corruption after final rename must refuse success");
        Check(mutatedExportObject && Directory.Exists(corruptedPortable),
            "untrusted published export preserved for inspection, never recursively deleted");

        string saltPortable = Path.Combine(sandbox, "export-readback-mutated-salt");
        bool mutatedExportSalt = false;
        MustFail(() => auditExport.ExportEncryptedSnapshotCore(auditedPoint, saltPortable,
            afterPublished: destination =>
            {
                string config = Path.Combine(destination, "repo.json");
                var json = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(config))!.AsObject();
                byte[] salt = Convert.FromBase64String(json["Salt"]!.GetValue<string>());
                salt[0] ^= 0x01; // Valid JSON, unchanged verifier and objects.
                json["Salt"] = Convert.ToBase64String(salt);
                File.WriteAllText(config, json.ToJsonString());
                mutatedExportSalt = true;
            }), "postpublication salt-only change must refuse unusable portable vault");
        Check(mutatedExportSalt && Directory.Exists(saltPortable),
            "salt-swapped published export preserved for inspection");
        auditExport.VerifySnapshot(auditedPoint);
    }
    Console.WriteLine("CHOMCIO_NATIVE_PUBLISHED_EXPORT_READBACK=PASS");

    // 0.1.43: A staged plaintext read-back must verify the physical HANDLE,
    // not only a FileInfo path followed by a separate FileStream(path) open.
    // Inject an identical-content replacement into the precise check/open gap.
    byte[] stagedFixture = "synthetic staged readback identity fixture"u8.ToArray();
    string stagedReadback = Path.Combine(sandbox, "staged-readback.txt");
    File.WriteAllBytes(stagedReadback, stagedFixture);
    string stagedDigest = Convert.ToHexString(SHA256.HashData(stagedFixture)).ToLowerInvariant();
    var stagedEntry = new LocalEncryptedVault.FileEntry("synthetic.txt", stagedFixture.Length,
        stagedDigest, new List<string>());
    LocalEncryptedVault.VerifyStagedFileOnDisk(stagedReadback, stagedEntry);
    Check(File.ReadAllBytes(stagedReadback).SequenceEqual(stagedFixture),
        "unmodified staged plaintext passes independent readback");
    if (OperatingSystem.IsWindows())
    {
        string replaceWith = Path.Combine(sandbox, "staged-identical-replacement.txt");
        string moveOriginalTo = Path.Combine(sandbox, "staged-original-moved.txt");
        File.WriteAllBytes(replaceWith, stagedFixture);
        File.SetLastWriteTimeUtc(replaceWith, File.GetLastWriteTimeUtc(stagedReadback));
        bool injectionExecuted = false;
        MustFail(() => LocalEncryptedVault.VerifyStagedFileOnDisk(stagedReadback, stagedEntry,
            beforeReadbackHandleOpen: () =>
            {
                File.Move(stagedReadback, moveOriginalTo);
                File.Move(replaceWith, stagedReadback);
                injectionExecuted = true;
            }), "replaced same-content staged file must fail identity check");
        Check(injectionExecuted, "replacement fault injection reached opened-handle boundary");
        Check(File.ReadAllBytes(moveOriginalTo).SequenceEqual(stagedFixture),
            "original staged content preserved after failed verification");
        Check(File.ReadAllBytes(stagedReadback).SequenceEqual(stagedFixture),
            "replacement really did have identical plaintext bytes");
    }
    Console.WriteLine("CHOMCIO_NATIVE_STAGED_NOFOLLOW_IDENTITY=PASS");

    // Security regression: Windows may delete an EMPTY private staging root
    // only through the verified original directory FILE_OBJECT. Path-recursive
    // failure cleanup is unsafe: a same-user actor could swap descendants.
    if (OperatingSystem.IsWindows())
    {
        string emptyStage = Path.Combine(sandbox, "cleanup-empty-original");
        Directory.CreateDirectory(emptyStage);
        bool renameDenied = false;
        using (var originalStage = WindowsPrivateRestoreStageGuard.Acquire(emptyStage))
        {
            Check(originalStage.TryDeleteOriginalEmptyStage(emptyStage, whileOwned: stage =>
            {
                try { Directory.Move(stage, stage + "-alien"); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                { renameDenied = true; }
            }), "original empty private stage disposed through retained handle");
        }
        Check(renameDenied && !Directory.Exists(emptyStage),
            "owned directory cannot be renamed during empty cleanup");

        string nonemptyStage = Path.Combine(sandbox, "cleanup-nonempty-preserved");
        Directory.CreateDirectory(nonemptyStage);
        File.WriteAllText(Path.Combine(nonemptyStage, "KEEP.txt"), "private original fixture");
        using (var originalStage = WindowsPrivateRestoreStageGuard.Acquire(nonemptyStage))
            Check(!originalStage.TryDeleteOriginalEmptyStage(nonemptyStage),
                "nonempty directory is NOT recursively deleted on Windows");
        Check(File.ReadAllText(Path.Combine(nonemptyStage, "KEEP.txt")) == "private original fixture",
            "existing staged descendants preserved pending reviewed cleanup");

        string swappedStage = Path.Combine(sandbox, "cleanup-foreign-preserved");
        string relocatedStage = Path.Combine(sandbox, "cleanup-original-relocated");
        string userData = Path.Combine(sandbox, "cleanup-unrelated-user-data");
        Directory.CreateDirectory(swappedStage);
        Directory.CreateDirectory(userData);
        File.WriteAllText(Path.Combine(userData, "VALUABLE.txt"), "leave unchanged");
        using (var originalStage = WindowsPrivateRestoreStageGuard.Acquire(swappedStage))
        {
            Directory.Move(swappedStage, relocatedStage);
            Directory.Move(userData, swappedStage);
            MustFail(() => originalStage.TryDeleteOriginalEmptyStage(swappedStage),
                "foreign directory inserted at private-stage basename must not be deleted");
            Check(File.ReadAllText(Path.Combine(swappedStage, "VALUABLE.txt")) == "leave unchanged",
                "unrelated substituted data survived owned cleanup refusal");
        }
        Console.WriteLine("CHOMCIO_NATIVE_HANDLE_BOUND_EMPTY_STAGE_CLEANUP=PASS");

        // Original single-file restore plaintext must be deleted through the
        // creation-time FileId and an owned non-share-delete handle. A swapped
        // same-name file is NOT an authorized cleanup target.
        string fileStage = PrivateRestoreStage.Create(fixtureStages, ".chomcio-file-restore-");
        string originalPayload = Path.Combine(fileStage, "payload.tmp");
        bool ownedFileRenameDenied = false;
        using (var pin = WindowsPrivateRestoreStageGuard.Acquire(fileStage))
        {
            WindowsOwnedSingleStageFileCleanup ownedPayload;
            using (var writer = new FileStream(originalPayload, FileMode.CreateNew,
                FileAccess.Write, FileShare.None))
            {
                ownedPayload = WindowsOwnedSingleStageFileCleanup.CaptureCreatedFile(
                    originalPayload, writer.SafeFileHandle);
                writer.Write("private staged plaintext"u8);
                writer.Flush(flushToDisk: true);
            }
            Check(ownedPayload.TryDeleteOriginal(pin, whileOwned: path =>
            {
                try { File.Move(path, path + "-alien"); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                { ownedFileRenameDenied = true; }
            }), "original owned plaintext file deleted through its FileId-checked handle");
            Check(ownedFileRenameDenied && !File.Exists(originalPayload),
                "plaintext basename could not be renamed while deletion handle owned it");
            Check(pin.TryDeleteOriginalEmptyStage(fileStage),
                "single-file cancellation leaves no private stage after owned cleanup");
        }

        string swappedFileStage = PrivateRestoreStage.Create(fixtureStages, ".chomcio-file-restore-");
        string swappedPayload = Path.Combine(swappedFileStage, "payload.tmp");
        string movedOriginalPayload = Path.Combine(swappedFileStage, "original-elsewhere.tmp");
        using (var pin = WindowsPrivateRestoreStageGuard.Acquire(swappedFileStage))
        {
            WindowsOwnedSingleStageFileCleanup ownedPayload;
            using (var writer = new FileStream(swappedPayload, FileMode.CreateNew,
                FileAccess.Write, FileShare.None))
            {
                ownedPayload = WindowsOwnedSingleStageFileCleanup.CaptureCreatedFile(
                    swappedPayload, writer.SafeFileHandle);
                writer.Write("original bytes"u8);
                writer.Flush(flushToDisk: true);
            }
            File.Move(swappedPayload, movedOriginalPayload);
            File.WriteAllText(swappedPayload, "FOREIGN VALUABLE BYTES");
            MustFail(() => ownedPayload.TryDeleteOriginal(pin),
                "substituted plaintext stage basename refuses deletion after FileId mismatch");
            Check(File.ReadAllText(swappedPayload) == "FOREIGN VALUABLE BYTES" &&
                File.ReadAllText(movedOriginalPayload) == "original bytes",
                "foreign replacement and moved original both survive cleanup refusal");
        }
        Console.WriteLine("CHOMCIO_NATIVE_OWNED_SINGLE_STAGE_FILE_CLEANUP=PASS");

        // An aborted multi-file restore must remove ONLY the physically owned
        // original files and empty newly-created nested directories. A foreign
        // filename moved into that tree must survive a failed cleanup attempt.
        string treeStage = PrivateRestoreStage.Create(fixtureStages, ".chomcio-restore-");
        using (var rootGuard = WindowsPrivateRestoreStageGuard.Acquire(treeStage))
        using (var treeCleanup = new WindowsOwnedRestoreTreeCleanup(treeStage))
        {
            string deepDirectory = Path.Combine(treeStage, "folder", "sub");
            PrivateRestoreStage.CreatePrivateSubdirectory(treeStage, deepDirectory,
                treeCleanup.TrackNewDirectory);
            string trackedFile = Path.Combine(deepDirectory, "owned.txt");
            using (var writer = new FileStream(trackedFile, FileMode.CreateNew, FileAccess.Write,
                FileShare.None))
            {
                treeCleanup.TrackCreatedFile(trackedFile, writer.SafeFileHandle);
                writer.Write("staged secret"u8);
            }
            Check(treeCleanup.TryCleanup(rootGuard),
                "owned recursive restore stage was cleaned without pathname recursion");
            Check(!Directory.Exists(treeStage),
                "cancelled owned restore leaves zero staged plaintext directories");
        }
        string foreignStage = PrivateRestoreStage.Create(fixtureStages, ".chomcio-restore-");
        string foreignRelocated = Path.Combine(sandbox, "original-recorded-payload");
        using (var rootGuard = WindowsPrivateRestoreStageGuard.Acquire(foreignStage))
        using (var treeCleanup = new WindowsOwnedRestoreTreeCleanup(foreignStage))
        {
            string nestedPath = Path.Combine(foreignStage, "nested");
            PrivateRestoreStage.CreatePrivateSubdirectory(foreignStage, nestedPath,
                treeCleanup.TrackNewDirectory);
            string tracked = Path.Combine(nestedPath, "recorded.txt");
            using (var writer = new FileStream(tracked, FileMode.CreateNew, FileAccess.Write,
                FileShare.None))
            {
                treeCleanup.TrackCreatedFile(tracked, writer.SafeFileHandle);
                writer.Write("original secret"u8);
            }
            File.Move(tracked, foreignRelocated);
            File.WriteAllText(tracked, "UNRELATED FOREIGN DATA");
            MustFail(() => treeCleanup.TryCleanup(rootGuard),
                "swapped descendant refuses owned cleanup");
            Check(File.ReadAllText(tracked) == "UNRELATED FOREIGN DATA" &&
                File.ReadAllText(foreignRelocated) == "original secret",
                "foreign moved-in data and original tracked payload are preserved");
        }
        Console.WriteLine("CHOMCIO_NATIVE_OWNED_TREE_STAGE_CLEANUP=PASS");
        // A FOREIGN replacement in the LAST recorded original leaf must not
        // strand an unrelated FIRST recorded owned plaintext leaf. Cleanup
        // still fails closed overall and retains the foreign private-stage
        // directory, but must continue deleting separately verified FileIds.
        string partialOwnedStage = PrivateRestoreStage.Create(fixtureStages, ".chomcio-restore-");
        string partialForeignOriginal = Path.Combine(sandbox, "partial-original-relocated.txt");
        using (var partialGuard = WindowsPrivateRestoreStageGuard.Acquire(partialOwnedStage))
        using (var partialOwned = new WindowsOwnedRestoreTreeCleanup(partialOwnedStage))
        {
            string partialNested = Path.Combine(partialOwnedStage, "nested");
            PrivateRestoreStage.CreatePrivateSubdirectory(partialOwnedStage, partialNested,
                partialOwned.TrackNewDirectory);
            string partialSafePayload = Path.Combine(partialNested, "safe-owned.txt");
            using (var writer = new FileStream(partialSafePayload, FileMode.CreateNew,
                FileAccess.Write, FileShare.None))
            {
                partialOwned.TrackCreatedFile(partialSafePayload, writer.SafeFileHandle);
                writer.Write("SAFE_OWNED_SECRET"u8);
                writer.Flush(flushToDisk: true);
            }
            string partialForeignPayload = Path.Combine(partialNested, "last-recorded.txt");
            using (var writer = new FileStream(partialForeignPayload, FileMode.CreateNew,
                FileAccess.Write, FileShare.None))
            {
                partialOwned.TrackCreatedFile(partialForeignPayload, writer.SafeFileHandle);
                writer.Write("MOVED_OWNED_SECRET"u8);
                writer.Flush(flushToDisk: true);
            }
            File.Move(partialForeignPayload, partialForeignOriginal);
            File.WriteAllText(partialForeignPayload, "FOREIGN_KEEP");
            MustFail(() => partialOwned.TryCleanup(partialGuard),
                "swapped child still raises a strict cleanup failure after other owned leaf removal");
            Check(!File.Exists(partialSafePayload) && Directory.Exists(partialOwnedStage),
                "verified independent owned plaintext removed, foreign-containing stage retained");
            Check(File.ReadAllText(partialForeignPayload) == "FOREIGN_KEEP" &&
                File.ReadAllText(partialForeignOriginal) == "MOVED_OWNED_SECRET",
                "foreign replacement AND relocated original remain byte-exact and untouched");
        }
        Console.WriteLine("CHOMCIO_NATIVE_PARTIAL_OWNED_CLEANUP=PASS");

        // This regression detects the former CreateDirectory -> pathname
        // FileId capture race. The callback runs with the original NT-created
        // directory handle open and no delete sharing; concurrent rename MUST
        // fail before ownership is recorded. Never weaken this native gate.
        string atomicParent = PrivateRestoreStage.Create(fixtureStages, ".chomcio-restore-");
        using (var rootGuard = WindowsPrivateRestoreStageGuard.Acquire(atomicParent))
        {
            string originalChild = Path.Combine(atomicParent, "atomic-original");
            bool inspectedOriginal = false;
            PrivateRestoreStage.CreatePrivateSubdirectory(atomicParent, originalChild,
                (created, creator) =>
                {
                    Check(!creator.IsInvalid && !creator.IsClosed,
                        "atomic new child is passed via its still-open original handle");
                    using var pinned = WindowsPrivateRestoreStageGuard.AcquireFromOriginalCreation(
                        created, creator);
                    string swapped = Path.Combine(atomicParent, "bad-rename");
                    MustFail(() => Directory.Move(created, swapped),
                        "NT-created child cannot be renamed while its creator handle is held");
                    pinned.RequireMatches(created);
                    inspectedOriginal = true;
                });
            Check(inspectedOriginal && Directory.Exists(originalChild),
                "the original stage child was recorded before the creator handle closed");
            MustFail(() => WindowsAtomicStageChildCreator.Create(
                    atomicParent, "atomic-original", null),
                "FILE_CREATE must reject existing child and never adopt it");
            Directory.Delete(originalChild);
            Check(rootGuard.TryDeleteOriginalEmptyStage(atomicParent),
                "owned atomic test stage cleaned only after original child removed");
        }
        // A directory created by us may later be replaced with ANOTHER real,
        // private-ACL directory owned by the SAME Windows user. The restore
        // writer must reject that child before opening its plaintext file.
        string writeStage = PrivateRestoreStage.Create(fixtureStages, ".chomcio-restore-");
        using (var rootGuard = WindowsPrivateRestoreStageGuard.Acquire(writeStage))
        using (var ownedWriter = new WindowsOwnedRestoreTreeCleanup(writeStage))
        {
            string ownedParent = Path.Combine(writeStage, "original-child");
            string movedParent = Path.Combine(writeStage, "relocated-original");
            PrivateRestoreStage.CreatePrivateSubdirectory(writeStage, ownedParent,
                ownedWriter.TrackNewDirectory,
                path => ownedWriter.PinOwnedParentForWrite(path, rootGuard));
            string fileInChild = Path.Combine(ownedParent, "verified-writer.txt");
            using (var safeLease = ownedWriter.PinOwnedParentForWrite(ownedParent, rootGuard))
            {
                MustFail(() => Directory.Move(ownedParent, movedParent),
                    "parent must NOT be renamed during owned writer lease");
                using var writer = new FileStream(fileInChild, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None);
                ownedWriter.TrackCreatedFile(fileInChild, writer.SafeFileHandle);
                writer.Write("staged original plaintext"u8);
                writer.Flush(flushToDisk: true);
                safeLease.RequireMatches();
            }
            Directory.Move(ownedParent, movedParent);
            Directory.CreateDirectory(ownedParent);
            File.WriteAllText(Path.Combine(ownedParent, "foreign.txt"), "UNRELATED STAGE PARENT");
            MustFail(() => ownedWriter.PinOwnedParentForWrite(ownedParent, rootGuard),
                "must reject a replaced but real/private staged descendant before write");
            Check(File.ReadAllText(Path.Combine(ownedParent, "foreign.txt")) ==
                "UNRELATED STAGE PARENT", "foreign replacement preserved after refusal");
            File.Delete(Path.Combine(ownedParent, "foreign.txt"));
            Directory.Delete(ownedParent);
            Directory.Move(movedParent, ownedParent);
            string untracked = Path.Combine(writeStage, "untracked-but-private");
            Directory.CreateDirectory(untracked);
            MustFail(() => ownedWriter.PinOwnedParentForWrite(untracked, rootGuard),
                "untracked private-looking child cannot receive plaintext");
            Directory.Delete(untracked);
            Check(ownedWriter.TryCleanup(rootGuard),
                "safe owned writer and its tracked stage cleanup both succeed");
        }
        Console.WriteLine("CHOMCIO_NATIVE_STAGE_PARENT_WRITE_PIN=PASS");

        Console.WriteLine("CHOMCIO_NATIVE_ATOMIC_CHILD_OWNERSHIP=PASS");

    }

    string original = Path.Combine(sandbox, "source");
    string repo = Path.Combine(sandbox, "repository");
    Directory.CreateDirectory(original);
    string nested = Path.Combine(original, "pliki");
    Directory.CreateDirectory(nested);
    Directory.CreateDirectory(Path.Combine(original, "empty-parent", "empty-leaf"));
    File.WriteAllText(Path.Combine(nested, "żółw.txt"), string.Concat(Enumerable.Repeat("żółw\n", 300)));
    File.WriteAllBytes(Path.Combine(original, "empty.bin"), []);
    byte[] large = RandomNumberGenerator.GetBytes(LocalEncryptedVault.ChunkBytes + 117);
    File.WriteAllBytes(Path.Combine(original, "large.bin"), large);
    // 0.1.36: An unrelated directory substituted at a failed restore's
    // private staging path MUST NOT be recursively deleted by the error path.
    // Stage sharing permits the legitimate final rename, so verify the actual
    // 128-bit directory identity rather than relying on path-only checks.
    if (OperatingSystem.IsWindows())
    {
        string stage = Path.Combine(sandbox, "stage-identity-private");
        string movedStage = Path.Combine(sandbox, "stage-identity-moved");
        string unrelated = Path.Combine(sandbox, "stage-identity-unrelated");
        Directory.CreateDirectory(stage);
        Directory.CreateDirectory(unrelated);
        string valuable = Path.Combine(unrelated, "KEEP.txt");
        File.WriteAllText(valuable, "disposable keep fixture");
        using (var stageIdentity = WindowsPrivateRestoreStageGuard.Acquire(stage))
        {
            stageIdentity.RequireMatches(stage);
            Directory.Move(stage, movedStage);
            Directory.Move(unrelated, stage);
            MustFail(() => stageIdentity.RequireMatches(stage),
                "cleanup must refuse an unrelated directory substituted into staging");
            Check(File.ReadAllText(Path.Combine(stage, "KEEP.txt")) == "disposable keep fixture",
                "substituted user directory remains intact");
        }
        Console.WriteLine("CHOMCIO_NATIVE_PRIVATE_STAGE_IDENTITY=PASS");
    }

    // 0.1.37: The encrypted EXPORT stage also has a recursive error cleanup.
    // A different directory moved into that random path must be preserved.
    // Native assertions below exercise actual Windows directory IDs. The
    // export method's required guard wiring is checked separately in Python.
    if (OperatingSystem.IsWindows())
    {
        string parent = Path.Combine(sandbox, "export-parent-pinned");
        Directory.CreateDirectory(parent);
        using (WindowsRestoreParentPin.Acquire(parent))
        {
            string stage = Path.Combine(parent, ".chomcio-export-fixture");
            string moved = Path.Combine(parent, "original-export-stage-moved");
            string unrelated = Path.Combine(parent, "unrelated-export-user-tree");
            Directory.CreateDirectory(stage);
            Directory.CreateDirectory(unrelated);
            File.WriteAllText(Path.Combine(unrelated, "KEEP.txt"), "synthetic unrelated export fixture");
            using (var exportIdentity = WindowsPrivateRestoreStageGuard.Acquire(stage))
            {
                exportIdentity.RequireMatches(stage);
                Directory.Move(stage, moved);
                Directory.Move(unrelated, stage);
                MustFail(() => exportIdentity.RequireMatches(stage),
                    "export error cleanup must refuse a substituted directory");
                Check(File.ReadAllText(Path.Combine(stage, "KEEP.txt")) ==
                    "synthetic unrelated export fixture", "export cleanup preserves unrelated file");
            }
        }
        Console.WriteLine("CHOMCIO_NATIVE_EXPORT_STAGE_IDENTITY=PASS");
    }

    // 0.1.32: Do not permit a nested directory to be renamed/replaced with
    // a junction while the backup is reading source files. Assert real NTFS
    // rename denial while the native handles are held (not only a source scan).
    if (OperatingSystem.IsWindows())
    {
        string pinRoot = Path.Combine(sandbox, "source-tree-pin");
        string nestedPin = Path.Combine(pinRoot, "deep", "leaf");
        Directory.CreateDirectory(nestedPin);
        string emptyPinnedLeaf = Path.Combine(pinRoot, "empty-pinned-leaf");
        Directory.CreateDirectory(emptyPinnedLeaf);
        File.WriteAllText(Path.Combine(nestedPin, "note.txt"), "synthetic source");
        using (WindowsSourceTreePin.Acquire(pinRoot))
        {
            MustFail(() => Directory.Move(emptyPinnedLeaf, emptyPinnedLeaf + "-moved"),
                "empty source leaf must reject rename while pinned");
            MustFail(() => Directory.Move(Path.Combine(pinRoot, "deep"),
                Path.Combine(pinRoot, "deep-renamed")),
                "pinned source subdirectory must reject rename during a backup");
            MustFail(() => Directory.Move(pinRoot, pinRoot + "-renamed"),
                "pinned source root must reject rename during a backup");
            Check(File.ReadAllText(Path.Combine(nestedPin, "note.txt")) == "synthetic source",
                "pinned nested source remains readable");
        }
        Directory.Move(Path.Combine(pinRoot, "deep"),
            Path.Combine(pinRoot, "deep-renamed"));
        Check(Directory.Exists(Path.Combine(pinRoot, "deep-renamed", "leaf")),
            "source directory handles are released after backup");
        Console.WriteLine("CHOMCIO_NATIVE_SOURCE_TREE_PIN=PASS");
    }

    // A new nested directory can appear AFTER WindowsSourceTreePin scanned
    // the source but BEFORE CaptureSourceInventory. It must NOT be backed up
    // as though its contents were protected by the native directory pin.
    if (OperatingSystem.IsWindows())
    {
        string coverageRoot = Path.Combine(sandbox, "source-pin-inventory-coverage");
        string originalChild = Path.Combine(coverageRoot, "initial-nested");
        Directory.CreateDirectory(originalChild);
        File.WriteAllText(Path.Combine(originalChild, "original.txt"), "original-source");
        using (var coveragePin = WindowsSourceTreePin.Acquire(coverageRoot))
        {
            var captured = LocalEncryptedVault.CaptureSourceInventory(coverageRoot);
            coveragePin.RequireCoveredDirectoryInventory(captured.Keys);
            Check(true, "native original source directory handles cover the first inventory");
            string addedAfterPin = Path.Combine(originalChild, "added-after-pin");
            Directory.CreateDirectory(addedAfterPin);
            string foreign = Path.Combine(addedAfterPin, "untrusted.txt");
            File.WriteAllText(foreign, "foreign-data-must-never-be-consumed");
            var changed = LocalEncryptedVault.CaptureSourceInventory(coverageRoot);
            Check(changed.ContainsKey("d/initial-nested/added-after-pin"),
                "native fixture truly enumerated the late unpinned directory");
            MustFail(() => coveragePin.RequireCoveredDirectoryInventory(changed.Keys),
                "late nested directory cannot be silently accepted as pinned");
            Check(File.ReadAllText(foreign) == "foreign-data-must-never-be-consumed",
                "failclosed directory coverage does not modify any foreign child");
            Check(File.ReadAllText(Path.Combine(originalChild, "original.txt")) == "original-source",
                "failclosed directory coverage preserves all original source bytes");
        }
        Console.WriteLine("CHOMCIO_NATIVE_SOURCE_PIN_INVENTORY_COVERAGE=PASS");
    }

    // 0.1.31: A regular file (not a reparse point or hard link) could be
    // substituted after first inventory, and copied size/timestamps were not
    // sufficient to reject it before foreign bytes entered orphan ciphertext.
    // Exercise the same 128-bit file ID guard that backup/rehash now use.
    if (OperatingSystem.IsWindows())
    {
        string tracked = Path.Combine(sandbox, "identity-original.bin");
        string moved = Path.Combine(sandbox, "identity-original-moved.bin");
        string impostor = Path.Combine(sandbox, "identity-impostor.bin");
        File.WriteAllText(tracked, "expected-synthetic-bytes");
        File.WriteAllText(impostor, "unexpected-sensitive-bytes");
        var expected = WindowsSourceFileIdentity.CaptureFile(tracked);
        Check(expected.HasValue, "first Windows scan records a file ID");
        using (FileStream unchanged = WindowsNoFollowSourceReader.Open(tracked))
            WindowsSourceFileIdentity.RequireMatches(unchanged, expected, tracked);
        File.Move(tracked, moved);
        File.Move(impostor, tracked);
        using (FileStream replaced = WindowsNoFollowSourceReader.Open(tracked))
            MustFail(() => WindowsSourceFileIdentity.RequireMatches(replaced, expected, tracked),
                "different ordinary file ID must be rejected before reading its content");
        // An absent baseline identity cannot silently disable the guard.
        using (FileStream replaced = WindowsNoFollowSourceReader.Open(tracked))
            MustFail(() => WindowsSourceFileIdentity.RequireMatches(replaced, null, tracked),
                "missing initial Windows file ID must fail closed");
        Console.WriteLine("CHOMCIO_NATIVE_INITIAL_SOURCE_IDENTITY=PASS");
    }
    // 0.1.30: Source FileStream.Open(path) could follow a just-substituted
    // symlink AFTER the preceding reparse check, ingesting outside plaintext
    // into orphan encrypted objects even if no snapshot was published.
    // Test the real native CreateFile(OPEN_REPARSE_POINT) + handle attributes.
    if (OperatingSystem.IsWindows())
    {
        string sourceFixture = Path.Combine(sandbox, "nofollow-source-original.bin");
        string outsideFixture = Path.Combine(sandbox, "nofollow-source-outside.bin");
        string sourceLink = Path.Combine(sandbox, "nofollow-source-link.bin");
        File.WriteAllText(sourceFixture, "selected-synthetic-content");
        File.WriteAllText(outsideFixture, "synthetic-outside-secret");
        using (var checkedSource = WindowsNoFollowSourceReader.Open(sourceFixture))
        {
            using var reader = new StreamReader(checkedSource);
            Check(reader.ReadToEnd() == "selected-synthetic-content",
                "normal source remains readable by the no-follow guard");
        }
        bool hasSymlinkPrivilege = false;
        try
        {
            File.CreateSymbolicLink(sourceLink, outsideFixture);
            hasSymlinkPrivilege = true;
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        if (hasSymlinkPrivilege)
        {
            MustFail(() => { using var invalid = WindowsNoFollowSourceReader.Open(sourceLink); },
                "opened Windows source link itself must be rejected before read");
            File.Delete(sourceLink);
            string sourceMoved = Path.Combine(sandbox, "nofollow-source-moved.bin");
            MustFail(() =>
            {
                using var forbidden = WindowsNoFollowSourceReader.Open(sourceFixture, () =>
                {
                    File.Move(sourceFixture, sourceMoved);
                    File.CreateSymbolicLink(sourceFixture, outsideFixture);
                });
            }, "source symlink swapped exactly at handle-open boundary must be rejected");
            Check(!File.Exists(sourceLink) && File.Exists(sourceMoved),
                "test swapped the source at the exact open boundary");
            File.Delete(sourceFixture); // Only our synthetic symlink fixture.
            File.Move(sourceMoved, sourceFixture);
            Console.WriteLine("CHOMCIO_NATIVE_SOURCE_NOFOLLOW_HANDLE=PASS");
        }
        else
        {
            // Do not claim PASS without a real Windows symlink fixture.
            Console.WriteLine("CHOMCIO_NATIVE_SOURCE_NOFOLLOW_HANDLE=SKIPPED (symlink privileges)");
        }
    }

    // Direct, deterministic exercise of the same source inventory guard used
    // immediately before actual snapshot publication in BackupDirectory.
    string changing = Path.Combine(sandbox, "source-inventory-fixture");
    Directory.CreateDirectory(changing);
    string stable = Path.Combine(changing, "stable.txt");
    File.WriteAllText(stable, "before");
    var inventory = LocalEncryptedVault.CaptureSourceInventory(changing);
    LocalEncryptedVault.ThrowIfSourceInventoryChanged(changing, inventory);
    string late = Path.Combine(changing, "late.txt");
    File.WriteAllText(late, "appeared mid-backup");
    MustFail(() => LocalEncryptedVault.ThrowIfSourceInventoryChanged(changing, inventory),
        "new files are not silently omitted from a recovery point");
    File.Delete(late);
    inventory = LocalEncryptedVault.CaptureSourceInventory(changing);
    File.WriteAllText(stable, "modified and longer");
    MustFail(() => LocalEncryptedVault.ThrowIfSourceInventoryChanged(changing, inventory),
        "previously copied file modified later makes backup fail closed");
    inventory = LocalEncryptedVault.CaptureSourceInventory(changing);
    File.Delete(stable);
    MustFail(() => LocalEncryptedVault.ThrowIfSourceInventoryChanged(changing, inventory),
        "previously copied file deleted later makes backup fail closed");
    // BOUNDED CIPHERTEXT READ: Do not trust a path stat followed by an
    // unbounded File.ReadAllBytes on a separately resolved path. Confirm the
    // same opened handle enforces the limit, including the exact boundary.
    string bounded = Path.Combine(sandbox, "bounded-ciphertext.bin");
    byte[] safePayload = RandomNumberGenerator.GetBytes(257);
    File.WriteAllBytes(bounded, safePayload);
    Check(LocalEncryptedVault.ReadBoundedFile(bounded, 257).SequenceEqual(safePayload),
        "bounded ciphertext reader must preserve exact bytes");
    MustFail(() => LocalEncryptedVault.ReadBoundedFile(bounded, 256),
        "ciphertext beyond size limit must fail closed");
    File.WriteAllBytes(bounded, new byte[258]);
    MustFail(() => LocalEncryptedVault.ReadBoundedFile(bounded, 257),
        "oversized ciphertext must not be allocated by ReadAllBytes");
    Console.WriteLine("CHOMCIO_NATIVE_BOUNDED_CIPHERTEXT_READ=PASS");

    // 0.1.41: a checked encrypted-record path may be swapped to a hard link
    // EXACTLY between the preliminary reparse check and CreateFile. Reading
    // that external plaintext is forbidden even for a disposable fixture.
    // Unlike symbolic links, creating hard links on NTFS requires no developer
    // mode privilege. Exercise ReadBoundedFile itself (not merely its helper).
    if (OperatingSystem.IsWindows())
    {
        string format = new DriveInfo(Path.GetPathRoot(sandbox)!).DriveFormat;
        if (format.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
        {
            string record = Path.Combine(sandbox, "record-before-open.bin");
            string originalRecord = Path.Combine(sandbox, "record-original-moved.bin");
            string unrelated = Path.Combine(sandbox, "record-unrelated.bin");
            File.WriteAllBytes(record, [1, 2, 3, 4]);
            File.WriteAllBytes(unrelated, [9, 8, 7, 6]);
            // The ordinary original must still be readable with exact length.
            Check(LocalEncryptedVault.ReadBoundedFile(record, 4).SequenceEqual(new byte[] {1, 2, 3, 4}),
                "regular encrypted record is read unchanged");
            bool replacedAtBoundary = false;
            MustFail(() => LocalEncryptedVault.ReadBoundedFile(record, 4, () =>
            {
                File.Move(record, originalRecord);
                WindowsHardLinkFixture.Create(record, unrelated);
                replacedAtBoundary = true;
            }), "encrypted-record hard link substituted at handle-open boundary must fail closed");
            Check(replacedAtBoundary && File.ReadAllBytes(unrelated).SequenceEqual(new byte[] {9, 8, 7, 6}),
                "synthetic external file remains unchanged after rejected record read");
            File.Delete(record); // Our test-created hard link ONLY.
            File.Move(originalRecord, record);
            Console.WriteLine("CHOMCIO_NATIVE_CIPHERTEXT_NOFOLLOW=PASS");
        }
        else
        {
            Console.WriteLine("CHOMCIO_NATIVE_CIPHERTEXT_NOFOLLOW=SKIPPED (test volume not NTFS)");
        }
    }

    // 0.1.28: every authenticated chunk must match the canonical fixed-size
    // encoder, not merely produce the right total SHA-256. These tests call
    // the actual C# guard used by VERIFY and both restore pipelines.
    LocalEncryptedVault.RequireCanonicalChunkLength(
        LocalEncryptedVault.ChunkBytes + 117L, 0, 2, LocalEncryptedVault.ChunkBytes);
    LocalEncryptedVault.RequireCanonicalChunkLength(
        LocalEncryptedVault.ChunkBytes + 117L, 1, 2, 117);
    LocalEncryptedVault.RequireCanonicalChunkLength(1, 0, 1, 1);
    MustFail(() => LocalEncryptedVault.RequireCanonicalChunkLength(1, 0, 1, 1200),
        "signed short file must not write oversized plaintext chunk");
    MustFail(() => LocalEncryptedVault.RequireCanonicalChunkLength(
        LocalEncryptedVault.ChunkBytes + 1L, 0, 2, 1),
        "nonfinal short chunk is not a valid canonical layout");
    MustFail(() => LocalEncryptedVault.RequireCanonicalChunkLength(
        LocalEncryptedVault.ChunkBytes + 1L, 1, 2, LocalEncryptedVault.ChunkBytes),
        "oversized final chunk is rejected before staging");
    MustFail(() => LocalEncryptedVault.RequireCanonicalChunkLength(0, 0, 0, 1),
        "empty file cannot claim any encrypted data chunk");
    Console.WriteLine("CHOMCIO_NATIVE_CANONICAL_CHUNK_LAYOUT=PASS");

    // Native C# source guard tests: EFS decryption, NTFS decompression or sparse-file expansion
    // cannot silently be presented as lossless NTFS restoration. These test the
    // predicate without requiring EFS certificates or kernel IOCTL permissions.
    foreach (FileAttributes unsupported in new[]
        { FileAttributes.Encrypted, FileAttributes.SparseFile, FileAttributes.Offline, FileAttributes.Compressed })
    {
        MustFail(() => WindowsUnsupportedMetadataGuard.RejectFlags(
            FileAttributes.Archive | unsupported, "synthetic-ntfs-entry"),
            "unsupported NTFS feature must be rejected: " + unsupported);
    }
    WindowsUnsupportedMetadataGuard.RejectFlags(
        FileAttributes.Archive | FileAttributes.ReadOnly | FileAttributes.Hidden,
        "ordinary-file");
    Check(true, "ordinary attributes remain admissible by this guard");
    Console.WriteLine("CHOMCIO_NATIVE_NTFS_METADATA_GUARD=PASS (synthetic flags)");

    // A legacy v1 snapshot has no folder list. An authenticated manifest
    // containing file reports AND file reports/2026.txt used to pass VERIFY
    // even though restore could never create both paths. Check actual C# code.
    static LocalEncryptedVault.FileEntry EmptyNamed(string name) =>
        new(name, 0, Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant(), new List<string>());
    foreach (var badPaths in new[]
    {
        new[] { "reports", "reports/2026.txt" },
        new[] { "reports", "REPORTS/2026.txt" },
        new[] { "records/2026", "records/2026/October/note.txt" }
    })
    {
        MustFail(() => LocalEncryptedVault.ValidateEntries(badPaths.Select(EmptyNamed).ToList()),
            "a file cannot also be an ancestor directory of another file");
    }
    LocalEncryptedVault.ValidateEntries(new[]
    {
        EmptyNamed("reports/2026/October.txt"),
        EmptyNamed("reports/2026/November.txt")
    });
    Console.WriteLine("CHOMCIO_NATIVE_PARENT_FILE_COLLISION=PASS");

    // WIN32 DOS DEVICE ALIASES: Windows treats ¹²³ as COM/LPT device digits;
    // console pseudo-devices CONIN$ and CONOUT$ are not ordinary files.
    // Verify the actual C# guard, not only a Python/source-code assertion.
    foreach (string deviceName in new[]
        { "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³", "CONIN$", "CONOUT$" })
    {
        MustFail(() => LocalEncryptedVault.ValidateRelativePath(deviceName + ".txt"),
            "reserved Win32 device name must not be a restorable file: " + deviceName);
        MustFail(() => LocalEncryptedVault.ValidateRelativePath("folder/" + deviceName),
            "reserved Win32 device name must not be a directory: " + deviceName);
    }
    foreach (string paddedAlias in new[] { "COM1 .txt", "LPT² .log", "CONIN$ .txt" })
        MustFail(() => LocalEncryptedVault.ValidateRelativePath(paddedAlias),
            "Win32 device alias padded before an extension must be rejected");
    foreach (string validName in new[]
        { "COM¹-report.txt", "LPT²-extra", "CONIN$-notes.txt", "reports/CONOUT$-meta.txt" })
    {
        LocalEncryptedVault.ValidateRelativePath(validName);
        Check(true, "non-device path name remains legal: " + validName);
    }
    Console.WriteLine("CHOMCIO_NATIVE_WIN32_DEVICE_PATH_GUARD=PASS");

    // The pin is Windows-only; Linux/Python cannot claim this Windows guarantee.
    // Test against an actual directory rename (not a mocked predicate).
    if (OperatingSystem.IsWindows())
    {
        string pinParent = Path.Combine(sandbox, "pin-test-parent");
        string pinRenamed = Path.Combine(sandbox, "pin-test-renamed");
        Directory.CreateDirectory(pinParent);
        var pin = WindowsRestoreParentPin.Acquire(pinParent);
        using (pin)
        {
            pin.RequireMatches();
            bool refused = false;
            try { Directory.Move(pinParent, pinRenamed); }
            catch (IOException) { refused = true; }
            catch (UnauthorizedAccessException) { refused = true; }
            // Do not turn a successful rename into PASS: later pipeline tests
            // still require that the destination ancestry cannot move.
            Check(refused, "pinned directory cannot be renamed by a concurrent operation");
            Check(Directory.Exists(pinParent) && !Directory.Exists(pinRenamed),
                "parent pin leaves original path stable");
            pin.RequireMatches();
            // The parent itself is pinned, but legitimate child publication
            // must still work while its handle remains open.
            string child = Path.Combine(pinParent, "child-stage");
            string childMoved = Path.Combine(pinParent, "child-moved");
            Directory.CreateDirectory(child);
            File.WriteAllText(Path.Combine(child, "fixture.txt"), "synthetic child publication");
            Directory.Move(child, childMoved);
            Check(File.ReadAllText(Path.Combine(childMoved, "fixture.txt")) ==
                "synthetic child publication", "parent pin permits child publication");
            pin.RequireMatches();
        }
        bool disposedRefused = false;
        try { pin.RequireMatches(); }
        catch (ObjectDisposedException) { disposedRefused = true; }
        Check(disposedRefused, "disposed parent pin must refuse validation");
        pin.Dispose(); // Repeated dispose is safe and must not re-open handles.
        Directory.Move(pinParent, pinRenamed);
        Check(Directory.Exists(pinRenamed), "pinned ancestor is released after Dispose");
        Console.WriteLine("CHOMCIO_NATIVE_RESTORE_PARENT_PIN=PASS");
        Console.WriteLine("CHOMCIO_NATIVE_RESTORE_PARENT_PIN_ACCESS=PASS");
    }
    string password = "testing-not-a-production-password-2026";
    LocalEncryptedVault.Initialize(repo, password);
    MustFail(() => LocalEncryptedVault.Open(repo, "wrong-password-12345"), "wrong password must fail");
    using (var vault = LocalEncryptedVault.Open(repo, password))
    {
        // Deliberately invalid AES-GCM tag: the decrypt output could contain
        // partial plaintext in a future provider/implementation. No such buffer
        // may remain populated after authentication failure or invalid shape.
        byte[] invalidAead = new byte[8 + 12 + 16 + 32];
        "CHMOBJ01"u8.CopyTo(invalidAead);
        byte[] poisonedPlaintext = Enumerable.Repeat((byte)0xA5, 32).ToArray();
        MustFail(() => vault.DecryptRecordInto(invalidAead, "CHMOBJ01"u8.ToArray(),
            "ChomcioRecovery/object/v1/invalid"u8.ToArray(), poisonedPlaintext),
            "invalid AES-GCM tag must refuse decryption");
        Check(poisonedPlaintext.All(b => b == 0),
            "failed authenticated decrypt zeroes destination plaintext");
        Array.Fill(poisonedPlaintext, (byte)0xA5);
        MustFail(() => vault.DecryptRecordInto(invalidAead, "WRONGMAG"u8.ToArray(),
            Array.Empty<byte>(), poisonedPlaintext),
            "invalid encrypted record header must fail closed");
        Check(poisonedPlaintext.All(b => b == 0),
            "invalid encrypted record zeroes destination plaintext");
        Console.WriteLine("CHOMCIO_NATIVE_DECRYPT_ZEROIZATION=PASS");
        // The current manifest schema has no representation for file hard-link
        // topology. Reject rather than silently restore independent copies.
        WindowsHardLinkGuard.RejectCount(1, "synthetic-single-link");
        MustFail(() => WindowsHardLinkGuard.RejectCount(0, "unknown-count"),
            "unknown hard-link count must fail closed");
        MustFail(() => WindowsHardLinkGuard.RejectCount(2, "multiple-links"),
            "multiple hard links are unsupported");
        if (OperatingSystem.IsWindows())
        {
            string hardLinkDir = Path.Combine(sandbox, "hard-link-source");
            Directory.CreateDirectory(hardLinkDir);
            string primary = Path.Combine(hardLinkDir, "content.txt");
            string alias = Path.Combine(sandbox, "hard-link-outside-source.txt");
            File.WriteAllText(primary, "this file also has a name OUTSIDE the selected folder");
            string driveFormat = new DriveInfo(Path.GetPathRoot(hardLinkDir)!).DriveFormat;
            if (string.Equals(driveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
            {
                // Windows hard-link creation does not require administrator
                // privileges and the fixture is on the same NTFS volume.
                WindowsHardLinkFixture.Create(alias, primary);
                try
                {
                    MustFail(() => WindowsHardLinkGuard.RejectMultipleLinks(primary),
                        "real NTFS multi-linked source file is rejected");
                    int before = vault.ListSnapshotIds().Count;
                    MustFail(() => vault.BackupDirectory(hardLinkDir),
                        "snapshot with outside-tree hard link is rejected");
                    Check(vault.ListSnapshotIds().Count == before,
                        "hard-linked source creates no recovery-point manifest");
                    Check(File.ReadAllText(alias) == File.ReadAllText(primary),
                        "rejection does not alter hard-linked source data");
                    Console.WriteLine("CHOMCIO_NATIVE_HARDLINK_CHECK=PASS");
                }
                finally { File.Delete(alias); }
                // Once the second name is gone, ordinary file backups work.
                var recovered = vault.BackupDirectory(hardLinkDir);
                string recoveredPath = Path.Combine(sandbox, "hard-link-now-independent-restore");
                vault.RestoreSnapshot(recovered.SnapshotId, recoveredPath);
                Check(File.ReadAllText(Path.Combine(recoveredPath, "content.txt")) ==
                      File.ReadAllText(primary), "single-link file still restores correctly");
            }
            else Console.WriteLine("CHOMCIO_NATIVE_HARDLINK_SKIP non-NTFS test volume");
        }
        MustFail(() => vault.BackupDirectory(sandbox), "repository inside source must fail");
        // Windows NTFS alternate data streams are not represented by this
        // file-only format. A "successful" backup must NOT silently omit them.
        // The check is really executed by Windows native smoke, not Python.
        if (OperatingSystem.IsWindows())
        {
            string adsRoot = Path.Combine(sandbox, "ads-source");
            Directory.CreateDirectory(adsRoot);
            string adsFile = Path.Combine(adsRoot, "normal.txt");
            File.WriteAllText(adsFile, "default stream is insufficient");
            string driveRoot = Path.GetPathRoot(adsRoot)!;
            if (string.Equals(new DriveInfo(driveRoot).DriveFormat, "NTFS",
                    StringComparison.OrdinalIgnoreCase))
            {
                string adsPath = adsFile + ":ChomcioRecoveryTestData";
                File.WriteAllText(adsPath, "secret named stream contents");
                Check(File.ReadAllText(adsPath) == "secret named stream contents",
                    "NTFS test fixture really created an alternate stream");
                int beforePointCount = vault.ListSnapshotIds().Count;
                try
                {
                    vault.BackupDirectory(adsRoot);
                    throw new Exception("TEST FAILED: named stream was silently omitted");
                }
                catch (IOException error)
                {
                    Check(error.Message.Contains("alternate stream", StringComparison.OrdinalIgnoreCase),
                        "NTFS backup failed specifically because an alternate stream was detected");
                }
                Check(vault.ListSnapshotIds().Count == beforePointCount,
                    "ADS rejection did not publish a misleading recovery point");
                Check(File.ReadAllText(adsPath) == "secret named stream contents",
                    "ADS rejection never changes existing source data");
                Console.WriteLine("CHOMCIO_NATIVE_ADS_CHECK=PASS");
                string namedDirectory = Path.Combine(sandbox, "ads-directory-source");
                Directory.CreateDirectory(namedDirectory);
                string dirStream = namedDirectory + ":ChomcioRecoveryDirStream";
                bool directoryAdsCreated = false;
                try
                {
                    File.WriteAllText(dirStream, "directory ADS payload");
                    directoryAdsCreated = true;
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("CHOMCIO_NATIVE_DIRECTORY_ADS_SKIP creation denied");
                }
                catch (IOException error)
                {
                    Console.WriteLine("CHOMCIO_NATIVE_DIRECTORY_ADS_SKIP creation error: " + error.Message);
                }
                if (directoryAdsCreated)
                {
                    Check(File.ReadAllText(dirStream) == "directory ADS payload",
                        "directory ADS fixture actually exists");
                    try
                    {
                        vault.BackupDirectory(namedDirectory);
                        throw new Exception("TEST FAILED: directory ADS silently omitted");
                    }
                    catch (IOException error)
                    {
                        Check(error.Message.Contains("alternate stream", StringComparison.OrdinalIgnoreCase),
                            "directory ADS rejected by specific guard");
                    }
                    Console.WriteLine("CHOMCIO_NATIVE_DIRECTORY_ADS_CHECK=PASS");
                }

            }
            else Console.WriteLine("CHOMCIO_NATIVE_ADS_SKIP: temporary volume not NTFS");
        }
        // CONTENT GUARD: timestamp, size and path-name checks alone can miss
        // an in-place rewrite with LastWriteTimeUtc restored to its old value.
        // Exercise the real SHA-256 re-read helper and manifest-last refusal.
        string sameSizeSource = Path.Combine(sandbox, "same-size-source");
        Directory.CreateDirectory(sameSizeSource);
        string sameSizeFile = Path.Combine(sameSizeSource, "bytes.txt");
        File.WriteAllText(sameSizeFile, "AAAAABBBBBCCCCC");
        var sameSizePoint = vault.BackupDirectory(sameSizeSource);
        var sameSizeManifest = vault.ReadSnapshot(sameSizePoint.SnapshotId);
        var sameSizeInventory = LocalEncryptedVault.CaptureSourceInventory(sameSizeSource);
        LocalEncryptedVault.VerifySourceContents(sameSizeSource, sameSizeManifest.Files, sameSizeInventory);
        DateTime unchangedWriteUtc = File.GetLastWriteTimeUtc(sameSizeFile);
        File.WriteAllText(sameSizeFile, "XXXXXYYYYYZZZZZ"); // exactly 15 bytes
        File.SetLastWriteTimeUtc(sameSizeFile, unchangedWriteUtc);
        MustFail(() => LocalEncryptedVault.VerifySourceContents(sameSizeSource,
            sameSizeManifest.Files, sameSizeInventory),
            "same-size source rewrite with restored timestamp is caught by full content hash");
        string invisiblePoint = Guid.NewGuid().ToString("N");
        MustFail(() => vault.PublishVerifiedSnapshot(invisiblePoint, sameSizeManifest,
            () => LocalEncryptedVault.VerifySourceContents(sameSizeSource,
                sameSizeManifest.Files, sameSizeInventory)),
            "changed source content must not publish a misleading recovery point");
        Check(!File.Exists(Path.Combine(repo, "snapshots", invisiblePoint + ".snap")),
            "source content mismatch leaves no committed manifest");
        vault.VerifySnapshot(sameSizePoint.SnapshotId); // Old valid point remains recoverable.
        Console.WriteLine("CHOMCIO_NATIVE_SOURCE_CONTENT_GUARD=PASS");

        // Private staging: this must perform a real Windows ACL creation, NOT
        // merely check a constant in source. Verify we can safely write into
        // the protected directory and that cleanup does not affect its parent.
        // Native ACL enforcement on NTFS/ReFS must be verified on Windows.
        string privateAclFixture = PrivateRestoreStage.Create(fixtureStages, ".chomcio-private-test-");
        try
        {
            Check(Directory.Exists(privateAclFixture), "private restore stage created");
            string stagedSecret = Path.Combine(privateAclFixture, "test-plaintext.bin");
            File.WriteAllBytes(stagedSecret, [42, 24]);
            Check(File.ReadAllBytes(stagedSecret).SequenceEqual(new byte[] {42, 24}),
                "private staged plaintext remains readable to restoring account");
        }
        finally { if (Directory.Exists(privateAclFixture)) Directory.Delete(privateAclFixture, true); }
        Check(!Directory.Exists(privateAclFixture), "private restore fixture removed");
        Console.WriteLine("CHOMCIO_NATIVE_PRIVATE_RESTORE_STAGE_CREATE=PASS");

        // Regression: nested restore directories must retain private security
        // even when their ambient Unix umask is permissive. The actual backup
        // and restore exercises below also include nested files/empty folders.
        string nestedPrivateFixture = PrivateRestoreStage.Create(fixtureStages, ".chomcio-private-nested-");
        try
        {
            string deepPrivate = Path.Combine(nestedPrivateFixture, "one", "two", "empty");
            PrivateRestoreStage.CreatePrivateSubdirectory(nestedPrivateFixture, deepPrivate);
            Check(Directory.Exists(deepPrivate), "nested private staging directories created");
            PrivateRestoreStage.CreatePrivateSubdirectory(nestedPrivateFixture, deepPrivate);
            Check(true, "idempotent private staging subdirectory check");
            MustFail(() => PrivateRestoreStage.CreatePrivateSubdirectory(nestedPrivateFixture, sandbox),
                "private staging subdirectory cannot escape staging root");
            if (!OperatingSystem.IsWindows())
            {
                const UnixFileMode publiclyReadable = UnixFileMode.GroupRead |
                    UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
                Check((File.GetUnixFileMode(deepPrivate) & publiclyReadable) == 0,
                    "nested staged directories are private on Unix");
                File.SetUnixFileMode(deepPrivate, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.UserExecute | UnixFileMode.OtherRead);
                MustFail(() => PrivateRestoreStage.CreatePrivateSubdirectory(nestedPrivateFixture, deepPrivate),
                    "unexpected permissive existing staged directory must fail closed");
            }
        }
        finally
        {
            if (Directory.Exists(nestedPrivateFixture)) Directory.Delete(nestedPrivateFixture, true);
        }
        Console.WriteLine("CHOMCIO_NATIVE_NESTED_RESTORE_PRIVACY=PASS");

        var first = vault.BackupDirectory(original);
        Check(first.Files == 3, "three files saved");
        var firstManifest = vault.ReadSnapshot(first.SnapshotId);
        // 0.1.53: cooperative STOP is a real public API contract, not a UI
        // animation. Cancelling preflight must not publish a recovery point or
        // leave decrypted staging. Cancel during precommit even AFTER every
        // encrypted object was independently read and authenticated.
        using (var alreadyCancelled = new CancellationTokenSource())
        {
            alreadyCancelled.Cancel();
            int beforeSnapshots = vault.ListSnapshotIds().Count;
            MustCancel(() => vault.BackupDirectory(original, alreadyCancelled.Token),
                "pre-cancelled backup throws OperationCanceledException");
            Check(vault.ListSnapshotIds().Count == beforeSnapshots,
                "pre-cancelled backup never publishes a snapshot");
            string preCancelledTree = Path.Combine(sandbox, "cancel-pre-tree");
            MustCancel(() => vault.RestoreSnapshot(first.SnapshotId, preCancelledTree,
                alreadyCancelled.Token), "pre-cancelled tree restore refused");
            Check(!Directory.Exists(preCancelledTree), "pre-cancelled tree absent");
            string preCancelledFile = Path.Combine(sandbox, "cancel-pre-file");
            MustCancel(() => vault.RestoreFile(first.SnapshotId, "large.bin",
                preCancelledFile, alreadyCancelled.Token), "pre-cancelled file restore refused");
            Check(!File.Exists(preCancelledFile), "pre-cancelled file absent");
        }
        using (var lateBackup = new CancellationTokenSource())
        {
            string refusedId = Guid.NewGuid().ToString("N");
            MustCancel(() => vault.PublishVerifiedSnapshot(refusedId, firstManifest,
                () => lateBackup.Cancel(), cancellationToken: lateBackup.Token),
                "cancellation after validated precommit stops manifest publication");
            Check(!File.Exists(Path.Combine(repo, "snapshots", refusedId + ".snap")),
                "cancelled precommit has no manifest filename");
            vault.VerifySnapshot(first.SnapshotId);
            Check(true, "existing verified snapshot survives precommit cancellation");
        }
        int stagingBefore = Directory.EnumerateDirectories(sandbox, ".chomcio-*", SearchOption.TopDirectoryOnly).Count();
        using (var lateRestore = new CancellationTokenSource())
        {
            string refusedTree = Path.Combine(sandbox, "cancel-late-tree");
            MustCancel(() => vault.RestoreSnapshotCore(first.SnapshotId, refusedTree,
                stage => lateRestore.Cancel(), cancellationToken: lateRestore.Token),
                "cancellation after decrypting full tree prevents publication");
            Check(!Directory.Exists(refusedTree), "cancelled decrypted tree never published");
        }
        using (var lateFile = new CancellationTokenSource())
        {
            string refusedFile = Path.Combine(sandbox, "cancel-late-file");
            MustCancel(() => vault.RestoreFileCore(first.SnapshotId, "large.bin", refusedFile,
                stage => lateFile.Cancel(), cancellationToken: lateFile.Token),
                "cancellation after decrypting one file prevents publication");
            Check(!File.Exists(refusedFile), "cancelled decrypted file never published");
        }
        Check(Directory.EnumerateDirectories(sandbox, ".chomcio-*", SearchOption.TopDirectoryOnly).Count() == stagingBefore,
            "cancelled restores clean their own private stages");
        Console.WriteLine("CHOMCIO_NATIVE_COOPERATIVE_CANCEL=PASS");
        // 0.1.56-CANCEL-MERGE: protect two previously unexposed cancellation
        // boundaries using REAL disk operations and a fault-injected OS read.
        using (var cancelledVerify = new CancellationTokenSource())
        {
            cancelledVerify.Cancel();
            MustCancel(() => vault.VerifySnapshot(first.SnapshotId, cancelledVerify.Token),
                "pre-cancelled public verifier does not claim a verified result");
            vault.VerifySnapshot(first.SnapshotId); // Existing point remains valid.
        }
        using (var cancelRecord = new CancellationTokenSource())
        {
            string unpublished = Path.Combine(sandbox, "cancel-before-atomic-publish.obj");
            bool stageWritten = false;
            MustCancel(() => LocalEncryptedVault.WriteAtomic(unpublished,
                RandomNumberGenerator.GetBytes(132_000), temp =>
                {
                    stageWritten = File.Exists(temp);
                    cancelRecord.Cancel();
                }, cancelRecord.Token), "cancelled encrypted record not committed");
            Check(stageWritten && !File.Exists(unpublished),
                "cancelled atomic record leaves no published name");
            Check(!Directory.EnumerateFiles(sandbox, "cancel-before-atomic-publish.obj.tmp-*").Any(),
                "cancelled record cleaned its OWN temp file");
        }
        using (var cancelRead = new CancellationTokenSource())
        using (var pendingRead = new StopAfterFirstReadStream(new byte[250_000], cancelRead.Cancel))
        {
            byte[] data = new byte[250_000];
            try
            {
                MustCancel(() => LocalEncryptedVault.ReadChunk(pendingRead, data, cancelRead.Token),
                    "cancellation arriving while OS read is in progress is detected");
                Check(pendingRead.ReadCalls == 1 && pendingRead.LargestRequest <= 65_536,
                    "cancel-aware source read is bounded to 64KiB");
            }
            finally { CryptographicOperations.ZeroMemory(data); }
        }
        Console.WriteLine("CHOMCIO_NATIVE_CANCELLATION_IO=PASS");
        // Cancellation during a many-entry source inventory must be cooperative:
        // the caller cannot wait for an entire slow disk tree just to stop.
        // All fixtures are under the disposable native test sandbox.
        string cancelScanRoot = Path.Combine(sandbox, "cancel-inventory-source");
        string cancelScanSub = Path.Combine(cancelScanRoot, "onlyDir", "nested");
        Directory.CreateDirectory(cancelScanSub);
        File.WriteAllText(Path.Combine(cancelScanSub, "payload.bin"), "keep-me");
        using (var inventoryStop = new CancellationTokenSource())
        {
            int scanned = 0;
            MustCancel(() => LocalEncryptedVault.CaptureSourceInventory(cancelScanRoot,
                inventoryStop.Token, visited =>
                {
                    scanned = visited;
                    if (visited == 2) inventoryStop.Cancel();
                }), "STOP interrupts actual source inventory before all entries");
            Check(scanned == 2, "source inventory STOP occurred at second discovered entry");
        }
        var intactInventory = LocalEncryptedVault.CaptureSourceInventory(cancelScanRoot);
        using (var repeatStop = new CancellationTokenSource())
        {
            int scanned = 0;
            MustCancel(() => LocalEncryptedVault.ThrowIfSourceInventoryChanged(cancelScanRoot,
                intactInventory, repeatStop.Token, visited =>
                {
                    scanned = visited;
                    if (visited == 2) repeatStop.Cancel();
                }), "STOP interrupts repeated inventory comparison before manifest commit");
            Check(scanned == 2, "second inventory STOP was mid-enumeration");
        }
        if (OperatingSystem.IsWindows())
        {
            using var pinStop = new CancellationTokenSource();
            int pinnedEntries = 0;
            MustCancel(() =>
            {
                using var partialPin = WindowsSourceTreePin.Acquire(cancelScanRoot,
                    pinStop.Token, visited =>
                    {
                        pinnedEntries = visited;
                        if (visited == 3) pinStop.Cancel();
                    });
            }, "STOP interrupts native source directory pin scan");
            Check(pinnedEntries == 3, "native pin STOP triggered after opening real nested directory handles");
            string relocatedScanRoot = cancelScanRoot + "-after-cancel";
            Directory.Move(cancelScanRoot, relocatedScanRoot);
            Check(File.ReadAllText(Path.Combine(relocatedScanRoot, "onlyDir", "nested", "payload.bin")) == "keep-me",
                "native pin cancellation released all directory handles and preserved source data");
            Directory.Move(relocatedScanRoot, cancelScanRoot);
        }
        Check(File.ReadAllText(Path.Combine(cancelScanSub, "payload.bin")) == "keep-me",
            "cancelling inventories does not modify source contents");
        Console.WriteLine("CHOMCIO_NATIVE_INVENTORY_ENUMERATION_CANCEL=PASS");


        // RESTORE SPACE PREFLIGHT: deterministically simulate an almost-full
        // volume; do not actually fill the disk. Refuse BEFORE a plaintext
        // stage is created and keep the valid encrypted recovery point intact.
        string spaceSandbox = Path.Combine(sandbox,"space-preflight");
        Directory.CreateDirectory(spaceSandbox);
        long restoreBytes = firstManifest.Files.Sum(entry => entry.Size);
        MustFail(() => RestoreSpaceGuard.RequireAvailable(spaceSandbox,
            new[] { long.MaxValue, 1L }, _ => long.MaxValue),
            "overflowing logical restore size is rejected");
        MustFail(() => RestoreSpaceGuard.RequireAvailable(spaceSandbox,
            new[] { -1L }, _ => long.MaxValue),
            "negative logical restore size is rejected");
        RestoreSpaceGuard.RequireAvailable(spaceSandbox, new[] { restoreBytes },
            _ => checked(restoreBytes + RestoreSpaceGuard.SafetyReserveBytes));
        Check(true, "sufficient-space preflight accepts the exact reserve boundary");
        string noSpaceTree = Path.Combine(spaceSandbox, "no-space-recovered-tree");
        MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, noSpaceTree, null,
            _ => restoreBytes),
            "whole-directory restore refuses missing safety reserve");
        string noSpaceFile = Path.Combine(spaceSandbox, "no-space-selected-file.txt");
        MustFail(() => vault.RestoreFileCore(first.SnapshotId, "large.bin", noSpaceFile, null,
            _ => 1L),
            "selected-file restore refuses low free capacity");
        Check(!Directory.Exists(noSpaceTree) && !File.Exists(noSpaceFile),
            "low-space restore published no destination");
        Check(!Directory.EnumerateFileSystemEntries(spaceSandbox)
            .Any(path => Path.GetFileName(path).StartsWith(".chomcio-restore-", StringComparison.Ordinal) ||
                         Path.GetFileName(path).StartsWith(".chomcio-file-restore-", StringComparison.Ordinal)),
            "low-space restore created no decrypted staging artifacts");
        vault.VerifySnapshot(first.SnapshotId);
        Console.WriteLine("CHOMCIO_NATIVE_RESTORE_SPACE_PREFLIGHT=PASS");
        if (OperatingSystem.IsWindows())
        {
            // Exercise the real restore pipeline, not merely Acquire(): the
            // destination parent must be unrenameable during stage/readback.
            string guardedParent = Path.Combine(sandbox, "guarded-restore-parent");
            string movedParent = Path.Combine(sandbox, "guarded-restore-parent-moved");
            Directory.CreateDirectory(guardedParent);
            bool attemptedDirectorySwap = false;
            string guardedTree = Path.Combine(guardedParent, "restored-tree");
            vault.RestoreSnapshotCore(first.SnapshotId, guardedTree, stage =>
            {
                attemptedDirectorySwap = true;
                bool rejected = false;
                try { Directory.Move(guardedParent, movedParent); }
                catch (IOException) { rejected = true; }
                catch (UnauthorizedAccessException) { rejected = true; }
                Check(rejected && Directory.Exists(stage),
                    "restore destination ancestry cannot move before readback");
            });
            Check(attemptedDirectorySwap && File.Exists(Path.Combine(guardedTree, "large.bin")),
                "pinned whole restore publishes verified bytes to original location");
            string guardedFile = Path.Combine(guardedParent, "restored-selected.bin");
            bool attemptedFileSwap = false;
            vault.RestoreFileCore(first.SnapshotId, "large.bin", guardedFile, stage =>
            {
                attemptedFileSwap = true;
                bool rejected = false;
                try { Directory.Move(guardedParent, movedParent); }
                catch (IOException) { rejected = true; }
                catch (UnauthorizedAccessException) { rejected = true; }
                Check(rejected && File.Exists(stage),
                    "selected-file restore destination ancestry cannot be renamed");
            });
            Check(attemptedFileSwap && File.ReadAllBytes(guardedFile).SequenceEqual(large),
                "pinned selected-file restore still recovers exact original bytes");
            Console.WriteLine("CHOMCIO_NATIVE_RESTORE_PARENT_PIN_PIPELINE=PASS");
        }
        // PATH NORMALIZATION: a path with an actual `alias/../repository`
        // component must NOT bypass the overlap check or publish plaintext
        // into the encrypted repository. C# GetFullPath handles this; make
        // native regression tests cover every API and both ancestor directions.
        string pathAlias = Path.Combine(sandbox, "dotdot-alias");
        Directory.CreateDirectory(pathAlias);
        string aliasedRepository = Path.Combine(pathAlias, "..", "repository");
        string illicitRestore = Path.Combine(aliasedRepository, "plaintext-tree");
        string illicitFile = Path.Combine(aliasedRepository, "plaintext-file.txt");
        string illicitExport = Path.Combine(aliasedRepository, "export-vault");
        MustFail(() => LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo, illicitRestore),
            "normalized dot-dot destination inside repository must be rejected");
        MustFail(() => LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo, Path.Combine(pathAlias, "..")),
            "normalized dot-dot ancestor containing repository must be rejected");
        LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo, Path.Combine(pathAlias, "..", "independent-new-destination"));
        Check(true, "disjoint path with harmless dot-dot remains supported");
        MustFail(() => vault.BackupDirectory(aliasedRepository),
            "aliased repository cannot be backed up as its own source");
        MustFail(() => vault.RestoreSnapshot(first.SnapshotId, illicitRestore),
            "dot-dot path cannot restore plaintext tree inside repository");
        MustFail(() => vault.RestoreFile(first.SnapshotId, "large.bin", illicitFile),
            "dot-dot path cannot restore plaintext file inside repository");
        MustFail(() => vault.ExportEncryptedSnapshot(first.SnapshotId, illicitExport),
            "dot-dot path cannot export into repository");
        MustFail(() => vault.ImportEncryptedSnapshot(first.SnapshotId, aliasedRepository),
            "dot-dot path cannot import the repository into itself");
        Check(!Directory.Exists(illicitRestore) && !Directory.Exists(illicitExport) &&
              !File.Exists(illicitFile),
            "none of the forbidden operations published inside the repository");
        vault.VerifySnapshot(first.SnapshotId);
        Console.WriteLine("CHOMCIO_NATIVE_NORMALIZED_PATH_OVERLAP_GUARD=PASS");
        // VOLUME ROOT: Path.TrimEndingDirectorySeparator preserves roots like
        // C:\ and /. A naive root + DirectorySeparatorChar would become C:\\
        // (or //), falsely claiming the entire volume does not contain this vault.
        // IMPORTANT: only test the predicate; NEVER enumerate the volume root.
        string volumeRoot = Path.GetPathRoot(repo)
            ?? throw new IOException("Repository volume root unavailable.");
        MustFail(() => LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo, volumeRoot),
            "filesystem volume root contains encrypted repository");
        MustFail(() => LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo,
                Path.Combine(volumeRoot, ".")),
            "normalized volume-root alias contains encrypted repository");
        LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo, Path.Combine(sandbox, "repository-neighbor"));
        Check(true, "same-parent sibling remains disjoint after volume-root fix");
        Console.WriteLine("CHOMCIO_NATIVE_VOLUME_ROOT_OVERLAP_GUARD=PASS");
        // 0.1.44: Windows 8.3 DOS short names can refer to the same REAL
        // directory while Path.GetFullPath returns a different lexical path.
        // The file-ID guard rejects these aliases before any backup/restore.
        // A short alias may be unavailable (8.3 disabled); report SKIPPED,
        // and keep the simpler real opened-handle overlap check mandatory.
        MustFail(() => WindowsRepositoryOverlapGuard.RejectPhysicalOverlap(repo,
                Path.Combine(repo, "unencrypted-child")),
            "physical repository ID blocks a not-yet-created child");
        WindowsRepositoryOverlapGuard.RejectPhysicalOverlap(repo,
            Path.Combine(sandbox, "safe-new-sibling"));
        Console.WriteLine("CHOMCIO_NATIVE_PHYSICAL_OVERLAP_GUARD=PASS");
        string? shortSandbox = WindowsShortPathFixture.TryGetShortPath(sandbox);
        if (shortSandbox is not null)
            MustFail(() => LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo, shortSandbox),
                "physical alias of repository ancestor must refuse self-backup recursion");
        string? shortRepo = WindowsShortPathFixture.TryGetShortPath(repo);
        if (shortRepo is not null)
        {
            MustFail(() => LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo, shortRepo),
                "8.3 alias of repository cannot be used as a backup source");
            MustFail(() => LocalEncryptedVault.EnsureRepositoryPathDisjoint(repo,
                    Path.Combine(shortRepo, "unprotected-new-file.txt")),
                "8.3 alias of repository cannot hide restore destination");
            MustFail(() => vault.BackupDirectory(shortRepo),
                "8.3 repository alias must not be backed up into itself");
            Check(!File.Exists(Path.Combine(repo, "unprotected-new-file.txt")),
                "8.3 alias rejection must not publish plaintext into repository");
            Console.WriteLine("CHOMCIO_NATIVE_SHORT_NAME_OVERLAP=PASS");
        }
        else
        {
            Console.WriteLine("CHOMCIO_NATIVE_SHORT_NAME_OVERLAP=SKIPPED (8.3 alias unavailable)");
        }

        // CONFIG PIN: deleting/changing the repo salt after unlock could make a
        // newly written recovery point unreadable on the next program launch.
        // Exercise the real commit path and inject a config swap AFTER its
        // source check, not just a synthetic comparison helper.
        string configFile = Path.Combine(repo, "repo.json");
        byte[] configAtUnlock = File.ReadAllBytes(configFile);
        // A salt-only substitution can pass HMAC key-verifier checks. Captured
        // config bytes must match EXACT unlock-time bytes, including their salt.
        vault.EnsureCapturedConfigMatchesUnlock(configAtUnlock);
        Check(true, "unchanged captured export configuration is accepted");
        var fakeConfigJson = System.Text.Json.Nodes.JsonNode.Parse(configAtUnlock)!;
        fakeConfigJson["Salt"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        byte[] tamperedCapturedConfig = System.Text.Encoding.UTF8.GetBytes(fakeConfigJson.ToJsonString());
        MustFail(() => vault.EnsureCapturedConfigMatchesUnlock(tamperedCapturedConfig),
            "salt-only captured config must be rejected even if disk config is unchanged");
        Check(File.ReadAllBytes(configFile).SequenceEqual(configAtUnlock),
            "failed captured-config check leaves real source repository untouched");
        Console.WriteLine("CHOMCIO_NATIVE_CAPTURED_EXPORT_CONFIG_GUARD=PASS");
        string configSwapPoint = Guid.NewGuid().ToString("N");
        MustFail(() => vault.PublishVerifiedSnapshot(configSwapPoint, firstManifest, () =>
        {
            var parsed = System.Text.Json.Nodes.JsonNode.Parse(System.Text.Encoding.UTF8.GetString(configAtUnlock))!;
            parsed["Salt"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            File.WriteAllText(configFile, parsed.ToJsonString());
        }), "salt-only repository config mutation at last commit boundary is rejected");
        Check(!File.Exists(Path.Combine(repo, "snapshots", configSwapPoint + ".snap")),
            "changed config never publishes a manifest");
        MustFail(() => vault.BackupDirectory(original),
            "subsequent backup with changed config remains blocked");
        File.WriteAllBytes(configFile, configAtUnlock);
        vault.VerifySnapshot(first.SnapshotId);
        using (var reopened = LocalEncryptedVault.Open(repo, password))
            reopened.VerifySnapshot(first.SnapshotId);
        string configRecoveredPoint = vault.BackupDirectory(original).SnapshotId;
        vault.VerifySnapshot(configRecoveredPoint);
        Console.WriteLine("CHOMCIO_NATIVE_CONFIG_PIN_GUARD=PASS");
        // READ-ONLY LINEAGE: a still-open vault can decrypt old snapshots using
        // its in-memory key even if repo.json has been corrupted or its salt
        // replaced. This must not be reported as a healthy, reopenable vault.
        // Work only in the disposable sandbox. No existing user files touched.
        File.WriteAllBytes(configFile, tamperedCapturedConfig);
        try
        {
            MustFail(() => vault.ListSnapshotIds(),
                "listing refuses a changed unlock-time repository config");
            MustFail(() => vault.ReadSnapshot(first.SnapshotId),
                "reading refuses a changed unlock-time repository config");
            MustFail(() => vault.VerifySnapshot(first.SnapshotId),
                "verification refuses a changed unlock-time repository config");
            string blockedReadRestore = Path.Combine(sandbox, "blocked-lineage-restore");
            string blockedReadFile = Path.Combine(sandbox, "blocked-lineage-file.txt");
            MustFail(() => vault.RestoreSnapshot(first.SnapshotId, blockedReadRestore),
                "whole restore refuses changed repository config");
            MustFail(() => vault.RestoreFile(first.SnapshotId, "large.bin", blockedReadFile),
                "single restore refuses changed repository config");
            Check(!Directory.Exists(blockedReadRestore) && !File.Exists(blockedReadFile),
                "changed config never produces visible plaintext restore");
        }
        finally { File.WriteAllBytes(configFile, configAtUnlock); }
        // Inject a salt-only change *after plaintext has already been staged*.
        // The final lineage check must reject publication and clean the stage.
        string blockedLateRestore = Path.Combine(sandbox, "blocked-late-lineage-restore");
        bool reachedRestoreStage = false;
        try
        {
            MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, blockedLateRestore, stage =>
            {
                reachedRestoreStage = Directory.Exists(stage);
                File.WriteAllBytes(configFile, tamperedCapturedConfig);
            }), "late config mutation rejects directory-restore publication");
            Check(reachedRestoreStage && !Directory.Exists(blockedLateRestore),
                "late directory-restore mutation reached the stage and stayed invisible");
        }
        finally { File.WriteAllBytes(configFile, configAtUnlock); }
        string blockedLateFile = Path.Combine(sandbox, "blocked-late-lineage-file.txt");
        bool reachedFileStage = false;
        try
        {
            MustFail(() => vault.RestoreFileCore(first.SnapshotId, "large.bin", blockedLateFile, stage =>
            {
                reachedFileStage = File.Exists(stage);
                File.WriteAllBytes(configFile, tamperedCapturedConfig);
            }), "late config mutation rejects single-file publication");
            Check(reachedFileStage && !File.Exists(blockedLateFile),
                "late single-file mutation reached the stage and stayed invisible");
        }
        finally { File.WriteAllBytes(configFile, configAtUnlock); }
        vault.VerifySnapshot(first.SnapshotId); // Recovered config works again.
        Console.WriteLine("CHOMCIO_NATIVE_READONLY_LINEAGE_GUARD=PASS");
        // Check the vault never follows pre-existing directory junctions/symlinks
        // to write encrypted objects or manifests outside the chosen repository.
        // On Windows a non-admin account may not have symlink privileges; in that
        // environment record SKIP rather than incorrectly claiming the test ran.
        void AssertStorageLinkRejected(string storagePath, Action action, string label)
        {
            string parked = storagePath + ".parked";
            string outside = Path.Combine(sandbox, "outside-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(outside);
            string sentinel = Path.Combine(outside, "sentinel.txt");
            File.WriteAllText(sentinel, "unchanged");
            Directory.Move(storagePath, parked);
            bool linked = false;
            try
            {
                try
                {
                    Directory.CreateSymbolicLink(storagePath, outside);
                    linked = true;
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("CHOMCIO_NATIVE_SYMLINK_SKIP insufficient Windows privileges: " + label);
                }
                catch (IOException error)
                {
                    Console.WriteLine("CHOMCIO_NATIVE_SYMLINK_SKIP " + label + ": " + error.Message);
                }
                if (linked)
                {
                    nativeLinkChecksExecuted++;
                    MustFail(action, "reject redirected vault storage: " + label);
                    Check(File.ReadAllText(sentinel) == "unchanged" &&
                          Directory.EnumerateFiles(outside).Count() == 1,
                          "no encrypted objects or manifests escaped repository: " + label);
                }
            }
            finally
            {
                if (linked) Directory.Delete(storagePath); // Deletes the link, NOT its target.
                Directory.Move(parked, storagePath);
            }
        }
        AssertStorageLinkRejected(Path.Combine(repo, "objects"),
            () => vault.BackupDirectory(original), "objects root");
        AssertStorageLinkRejected(Path.Combine(repo, "snapshots"),
            () => vault.BackupDirectory(original), "snapshots root");
        AssertStorageLinkRejected(Path.Combine(repo, "objects"),
            () => vault.VerifySnapshot(first.SnapshotId), "readback objects root");
        AssertStorageLinkRejected(Path.Combine(repo, "snapshots"),
            () => vault.ReadSnapshot(first.SnapshotId), "readback snapshots root");
        // Reject a symlinked repo.json even if it points to the same bytes;
        // external config paths should never be trusted implicitly.
        string repoConfig = Path.Combine(repo, "repo.json");
        string configParked = Path.Combine(repo, "repo.json.parked");
        File.Move(repoConfig, configParked);
        bool configLinkCreated = false;
        try
        {
            try
            {
                File.CreateSymbolicLink(repoConfig, configParked);
                configLinkCreated = true;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("CHOMCIO_NATIVE_SYMLINK_SKIP repo.json (no privileges)");
            }
            catch (IOException error)
            {
                Console.WriteLine("CHOMCIO_NATIVE_SYMLINK_SKIP repo.json: " + error.Message);
            }
            if (configLinkCreated)
            {
                nativeLinkChecksExecuted++;
                MustFail(() => { using var rejected = LocalEncryptedVault.Open(repo, password); },
                    "repo.json symbolic-link configuration rejected");
            }
        }
        finally
        {
            if (configLinkCreated) File.Delete(repoConfig); // Delete link only.
            File.Move(configParked, repoConfig);
        }
        Check(firstManifest.Version == 2, "new snapshots use v2 schema");
        string lateChangePoint = Guid.NewGuid().ToString("N");
        MustFail(() => vault.PublishVerifiedSnapshot(lateChangePoint, firstManifest,
            () => throw new IOException("simulated source change after read-back")),
            "late source change refuses manifest publication");
        Check(!File.Exists(Path.Combine(repo, "snapshots", lateChangePoint + ".snap")),
            "late change did not expose any recovery point");
        Check(firstManifest.Directories is not null &&
              firstManifest.Directories.SequenceEqual(new[] { "empty-parent", "empty-parent/empty-leaf", "pliki" }),
              "v2 manifest includes all folders, including nested empty ones");
        Check(first.NewChunks >= 3, "multiple encrypted objects written");
        MustFail(() => LocalEncryptedVault.ValidateDirectoryTree(firstManifest.Files, null, 2),
            "v2 manifest missing explicit directory inventory rejected");
        MustFail(() => LocalEncryptedVault.ValidateDirectoryTree(firstManifest.Files,
            new List<string> { "empty-parent/empty-leaf", "pliki" }, 2),
            "v2 snapshot rejects missing ancestor");
        MustFail(() => LocalEncryptedVault.ValidateDirectoryTree(firstManifest.Files,
            new List<string> { "empty-parent", "EMPTY-PARENT", "empty-parent/empty-leaf", "pliki" }, 2),
            "v2 snapshot rejects case aliases");
        MustFail(() => LocalEncryptedVault.ValidateDirectoryTree(firstManifest.Files,
            new List<string> { "empty-parent", "empty-parent/empty-leaf", "pliki", "large.bin" }, 2),
            "v2 snapshot rejects file/directory collision");
        LocalEncryptedVault.ValidateDirectoryTree(firstManifest.Files, null, 1);
        string emptySource = Path.Combine(sandbox, "only-empty-directories");
        Directory.CreateDirectory(Path.Combine(emptySource, "nested", "no-files"));
        var emptyPoint = vault.BackupDirectory(emptySource);
        Check(emptyPoint.Files == 0, "zero file backup succeeds");
        Check(vault.ReadSnapshot(emptyPoint.SnapshotId).Directories?.Contains("nested/no-files") == true,
            "only-empty folders persist in manifest");
        string emptyRestore = Path.Combine(sandbox, "only-empty-restored");
        vault.RestoreSnapshot(emptyPoint.SnapshotId, emptyRestore);
        Check(Directory.Exists(Path.Combine(emptyRestore, "nested", "no-files")),
            "only-empty folder tree can be restored independently");
        vault.VerifySnapshot(first.SnapshotId);
        // The OUTPUT basename is supplied separately from the authenticated
        // manifest and must also obey Windows naming rules. Otherwise restoring
        // to CON.txt, an ADS path or trailing-dot alias is not reliably readable.
        foreach (string badLeaf in new[]
        {
            "CON.txt", "COM¹.bin", "LPT2 .txt", "CONOUT$.log",
            "restored:ads", "trailing.", "trailing ", "NUL"
        })
        {
            string badDestination = Path.Combine(sandbox, badLeaf);
            MustFail(() => LocalEncryptedVault.ValidatePublicationDestination(badDestination),
                "unrestorable publication basename is rejected: " + badLeaf);
            MustFail(() => vault.RestoreSnapshot(first.SnapshotId, badDestination),
                "folder restore refuses bad output name: " + badLeaf);
            MustFail(() => vault.RestoreFile(first.SnapshotId, "large.bin", badDestination),
                "single-file restore refuses bad output name: " + badLeaf);
            MustFail(() => vault.ExportEncryptedSnapshot(first.SnapshotId, badDestination),
                "encrypted export refuses bad output name: " + badLeaf);
            Check(!File.Exists(badDestination) && !Directory.Exists(badDestination),
                "rejected output remains absent: " + badLeaf);
        }
        LocalEncryptedVault.ValidatePublicationDestination(Path.Combine(sandbox, "COM1-notes.txt"));
        Check(true, "non-device basename is still legal");
        Console.WriteLine("CHOMCIO_NATIVE_PUBLICATION_DESTINATION_GUARD=PASS");

        string restoreA = Path.Combine(sandbox, "restoreA");
        vault.RestoreSnapshot(first.SnapshotId, restoreA);
        Check(Directory.Exists(Path.Combine(restoreA, "empty-parent", "empty-leaf")),
            "restore recreates nested empty directories");
        Check(!Directory.EnumerateFileSystemEntries(Path.Combine(restoreA, "empty-parent", "empty-leaf")).Any(),
            "restored empty directory remains empty");
        Check(File.ReadAllBytes(Path.Combine(restoreA, "large.bin")).SequenceEqual(large), "multichunk restore exact");
        Check(File.ReadAllText(Path.Combine(restoreA, "pliki", "żółw.txt")) == File.ReadAllText(Path.Combine(nested, "żółw.txt")), "Unicode exact");

        // Owned DIRECTORY publication: after the stage has been verified,
        // pathname-based Directory.Move could previously publish a different
        // tree swapped into the stage basename. Here the rename is issued on
        // the original DELETE-capable directory FILE_OBJECT itself.
        if (OperatingSystem.IsWindows())
        {
            string ownedStage = PrivateRestoreStage.Create(sandbox, ".chomcio-restore-");
            File.WriteAllText(Path.Combine(ownedStage, "owned.txt"), "owned-only");
            string ownedTarget = Path.Combine(sandbox, "owned-directory-commit");
            bool sourceRenameDenied = false;
            using (var pinnedStage = WindowsPrivateRestoreStageGuard.Acquire(ownedStage))
                WindowsOwnedDirectoryPublisher.Publish(ownedStage, ownedTarget, pinnedStage,
                    CancellationToken.None, whilePinned: source =>
                    {
                        try { Directory.Move(source, source + ".alien"); }
                        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                        { sourceRenameDenied = true; }
                    });
            Check(sourceRenameDenied, "owned directory handle denies source pathname replacement");
            Check(File.ReadAllText(Path.Combine(ownedTarget, "owned.txt")) == "owned-only",
                "original private directory FILE_OBJECT was published intact");
            Check(!Directory.Exists(ownedStage), "old stage basename disappeared after owned rename");

            string collisionStage = PrivateRestoreStage.Create(sandbox, ".chomcio-restore-");
            string collisionTarget = Path.Combine(sandbox, "owned-directory-collision");
            bool collided = false;
            using (var pinnedStage = WindowsPrivateRestoreStageGuard.Acquire(collisionStage))
                MustFail(() => WindowsOwnedDirectoryPublisher.Publish(collisionStage,
                    collisionTarget, pinnedStage, CancellationToken.None, whilePinned: _ =>
                    {
                        Directory.CreateDirectory(collisionTarget);
                        File.WriteAllText(Path.Combine(collisionTarget, "KEEP.txt"), "do not replace");
                        collided = true;
                    }), "owned directory no-replace commit refuses late destination collision");
            Check(collided && File.ReadAllText(Path.Combine(collisionTarget, "KEEP.txt")) ==
                "do not replace", "late colliding directory and contents are preserved");
            Check(Directory.Exists(collisionStage), "failed owned directory rename preserves stage");
            Directory.Delete(collisionStage, recursive: true); // disposable self-created stage only

            string cancelStage = PrivateRestoreStage.Create(sandbox, ".chomcio-restore-");
            string cancelTarget = Path.Combine(sandbox, "owned-directory-cancelled");
            using (var cancel = new CancellationTokenSource())
            using (var pinnedStage = WindowsPrivateRestoreStageGuard.Acquire(cancelStage))
                MustCancel(() => WindowsOwnedDirectoryPublisher.Publish(cancelStage,
                    cancelTarget, pinnedStage, cancel.Token,
                    whilePinned: _ => cancel.Cancel()),
                    "cancellation at owned directory commit prevents visibility");
            Check(!Directory.Exists(cancelTarget) && Directory.Exists(cancelStage),
                "cancelled directory commit preserves original stage, does not publish");
            Directory.Delete(cancelStage, recursive: true); // disposable stage only
            Console.WriteLine("CHOMCIO_NATIVE_HANDLE_BOUND_DIRECTORY_PUBLISH=PASS");
        }

        // 0.1.54: swap an already verified private stage immediately BEFORE
        // its final rename. Refuse publication instead of briefly exposing a
        // DIFFERENT and UNVERIFIED directory to the destination. The stage
        // handle intentionally allows rename so the fixture is meaningful.
        string stageSwapParent=Path.Combine(sandbox,"stage-swap-fixtures");Directory.CreateDirectory(stageSwapParent);
        string swappedTreeTarget = Path.Combine(stageSwapParent, "prepublish-tree-refused");
        string swappedTreeOriginal = Path.Combine(stageSwapParent, "prepublish-tree-original");
        string? substitutedTree = null;
        MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, swappedTreeTarget,
            beforeStageReadback: null, beforePublication: stage =>
            {
                Directory.Move(stage, swappedTreeOriginal);
                Directory.CreateDirectory(stage);
                File.WriteAllText(Path.Combine(stage, "KEEP-FOREIGN.txt"), "foreign");
                substitutedTree = stage;
            }), "restore must refuse stage directory swapped AFTER readback BEFORE commit");
        Check(substitutedTree is not null && Directory.Exists(swappedTreeOriginal),
            "native post-readback restore stage-swap hook really ran");
        Check(!Directory.Exists(swappedTreeTarget), "unverified tree never became visible");
        Check(File.Exists(Path.Combine(substitutedTree!, "KEEP-FOREIGN.txt")),
            "failed restore never deletes unrelated substituted directory");

        string swappedExportTarget = Path.Combine(stageSwapParent, "prepublish-export-refused");
        string swappedExportOriginal = Path.Combine(stageSwapParent, "prepublish-export-original");
        string? substitutedExport = null;
        MustFail(() => vault.ExportEncryptedSnapshotCore(first.SnapshotId, swappedExportTarget,
            afterPublished: null, beforePublication: stage =>
            {
                Directory.Move(stage, swappedExportOriginal);
                Directory.CreateDirectory(stage);
                File.WriteAllText(Path.Combine(stage, "KEEP-FOREIGN.txt"), "foreign");
                substitutedExport = stage;
            }), "export must refuse stage directory swapped AFTER readback BEFORE commit");
        Check(substitutedExport is not null && Directory.Exists(swappedExportOriginal),
            "native post-readback export stage-swap hook really ran");
        Check(!Directory.Exists(swappedExportTarget), "unverified encrypted export never became visible");
        Check(File.Exists(Path.Combine(substitutedExport!, "KEEP-FOREIGN.txt")),
            "failed export never deletes unrelated substituted directory");
        vault.VerifySnapshot(first.SnapshotId);
        Console.WriteLine("CHOMCIO_NATIVE_PREPUBLICATION_STAGE_IDENTITY=PASS");

        // 0.1.50: A successful staged readback alone is not enough. Corrupt
        // the published tree/file immediately AFTER its final rename, then
        // require the public restore pipeline to refuse a successful result.
        // Published names are deliberately preserved, never blindly deleted.
        string postPublishedTree = Path.Combine(sandbox, "post-published-corrupt-tree");
        bool postTreeInjection = false;
        MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, postPublishedTree,
            beforeStageReadback: null, afterPublished: published =>
            {
                string file = Path.Combine(published, "large.bin");
                using var changed = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                int old = changed.ReadByte();
                changed.Position = 0;
                changed.WriteByte((byte)(old ^ 0x01));
                changed.Flush(flushToDisk: true);
                postTreeInjection = true;
            }), "corrupt post-rename tree cannot be reported as restored");
        Check(postTreeInjection && File.Exists(Path.Combine(postPublishedTree, "large.bin")),
            "already-published tree is preserved after integrity rejection");
        string postPublishedFile = Path.Combine(sandbox, "post-published-corrupt-file.bin");
        bool postFileInjection = false;
        MustFail(() => vault.RestoreFileCore(first.SnapshotId, "large.bin", postPublishedFile,
            beforeStageReadback: null, afterPublished: published =>
            {
                using var changed = new FileStream(published, FileMode.Open, FileAccess.ReadWrite,
                    FileShare.None);
                int old = changed.ReadByte();
                changed.Position = 0;
                changed.WriteByte((byte)(old ^ 0x01));
                changed.Flush(flushToDisk: true);
                postFileInjection = true;
            }), "corrupt post-rename file cannot be reported as restored");
        Check(postFileInjection && File.Exists(postPublishedFile),
            "already-published file is preserved after integrity rejection");
        vault.VerifySnapshot(first.SnapshotId);
        Console.WriteLine("CHOMCIO_NATIVE_PUBLISHED_RESTORE_READBACK=PASS");

        // The original plaintext was safely published, but a later actor may
        // move it away and substitute a byte-identical DIFFERENT FILE_OBJECT.
        // Hash-only post-publish readback falsely reports success. This native
        // fixture must preserve both the moved original and foreign replacement.
        string swappedRestored = Path.Combine(sandbox, "post-published-foreign-restored.txt");
        string movedRestored = Path.Combine(sandbox, "post-published-creator-original.txt");
        bool foreignRestoreInjected = false;
        MustFail(() => vault.RestoreFileCore(first.SnapshotId, "pliki/żółw.txt", swappedRestored,
            beforeStageReadback: null, afterPublished: published =>
            {
                File.Move(published, movedRestored);
                File.Copy(movedRestored, published); // same exact bytes, different NTFS FileId
                foreignRestoreInjected = true;
            }), "byte-identical foreign restored file cannot confirm original publication");
        Check(foreignRestoreInjected && File.Exists(swappedRestored) && File.Exists(movedRestored),
            "foreign published restore and original creator file are both preserved");
        Check(File.ReadAllBytes(swappedRestored).SequenceEqual(File.ReadAllBytes(movedRestored)),
            "native foreign-file swap has identical bytes but different object identity");
        Console.WriteLine("CHOMCIO_NATIVE_CREATOR_BOUND_PLAINTEXT_READBACK=PASS");

        // A full restored tree previously checked only byte-exact file hashes
        // after root publication. Substitute a NEW same-byte ordinary NTFS
        // FILE_OBJECT at a known child pathname AFTER the original rename.
        // Both the moved original and inserted foreign file must survive an
        // explicit failed verification; no speculative post-commit deletion.
        string foreignTreeTarget = Path.Combine(sandbox, "post-published-foreign-full-tree");
        string movedTreeLeaf = Path.Combine(sandbox, "post-published-tree-original-leaf.txt");
        bool foreignTreeInjected = false;
        MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, foreignTreeTarget,
            beforeStageReadback: null, afterPublished: published =>
            {
                string originalLeaf = Path.Combine(published, "pliki", "żółw.txt");
                File.Move(originalLeaf, movedTreeLeaf);
                File.Copy(movedTreeLeaf, originalLeaf); // byte-identical FOREIGN FileId
                foreignTreeInjected = true;
            }), "published full-tree restore cannot adopt foreign byte-identical leaf");
        string foreignTreeLeaf = Path.Combine(foreignTreeTarget, "pliki", "żółw.txt");
        Check(foreignTreeInjected && File.Exists(foreignTreeLeaf) && File.Exists(movedTreeLeaf),
            "published original and foreign tree leaf must both be preserved");
        Check(File.ReadAllBytes(foreignTreeLeaf).SequenceEqual(File.ReadAllBytes(movedTreeLeaf)),
            "adversarial published tree leaf has identical bytes but a distinct FileId");
        Console.WriteLine("CHOMCIO_NATIVE_ORIGINAL_PUBLISHED_TREE_INVENTORY=PASS");

        // Deterministic disk-fault injection AFTER all plaintext write handles
        // have closed but BEFORE the restored folder can be published.
        string corruptedRestore = Path.Combine(sandbox, "restored-damaged-do-not-publish");
        bool corruptedHookRan = false;
        MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, corruptedRestore, stage =>
        {
            corruptedHookRan = true;
            File.WriteAllText(Path.Combine(stage, "large.bin"), "tampered post-write");
        }), "post-write tampering must fail closed for whole-folder restore");
        Check(corruptedHookRan && !Directory.Exists(corruptedRestore),
            "corrupted staged restore did not publish any destination");
        string foreignInjectionParent=Path.Combine(sandbox,"foreign-injection");Directory.CreateDirectory(foreignInjectionParent);
        string unexpectedRestore = Path.Combine(foreignInjectionParent, "restored-extra-do-not-publish");
        string? injectedForeignFile=null;
        bool extraHookRan = false;
        MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, unexpectedRestore, stage =>
        {
            extraHookRan = true;
            injectedForeignFile=Path.Combine(stage,"INJECTED.txt");
            File.WriteAllText(injectedForeignFile, "unexpected entry");
        }), "extra file in staging must fail closed");
        Check(extraHookRan && !Directory.Exists(unexpectedRestore),
            "restore rejected unexpected staging file");
        Check(injectedForeignFile is not null && File.ReadAllText(injectedForeignFile)=="unexpected entry" && Directory.EnumerateFiles(foreignInjectionParent,"*",SearchOption.AllDirectories).Count()==1, "foreign injected entry preserved while all owned plaintext is cleaned");
        Check(!Directory.EnumerateDirectories(sandbox, ".chomcio-restore-*").Any(),
            "failed directory restores cleaned up staging folders");

        string corruptedSingle = Path.Combine(sandbox, "single-damaged-do-not-publish.txt");
        bool singleHookRan = false;
        MustFail(() => vault.RestoreFileCore(first.SnapshotId, "pliki/żółw.txt", corruptedSingle, stage =>
        {
            singleHookRan = true;
            File.WriteAllText(stage, "bad file bytes after write");
        }), "post-write tampering must fail closed for single-file restore");
        Check(singleHookRan && !File.Exists(corruptedSingle),
            "corrupted single file is not published");
        Check(!Directory.EnumerateDirectories(sandbox, ".chomcio-file-restore-*").Any(),
            "failed single-file restore removed temporary output");

        // A Windows NTFS named alternate stream does not change the default
        // stream SHA-256. Previously single-file restore verified ONLY those
        // bytes and could publish an attacker-injected named stream. Exercise
        // the REAL public restore path via a deterministic pre-readback hook.
        if (OperatingSystem.IsWindows() && string.Equals(
                new DriveInfo(Path.GetPathRoot(sandbox)!).DriveFormat, "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            string adsInjectionDestination = Path.Combine(sandbox, "single-ads-do-not-publish.txt");
            bool injectedAdStream = false;
            MustFail(() => vault.RestoreFileCore(first.SnapshotId, "pliki/żółw.txt",
                adsInjectionDestination, stage =>
                {
                    string injectedPath = stage + ":ChomcioStageInjected";
                    File.WriteAllText(injectedPath, "hidden named stream must fail restore");
                    injectedAdStream = File.ReadAllText(injectedPath) ==
                        "hidden named stream must fail restore";
                }), "a named NTFS ADS added to a staged single-file restore must fail closed");
            Check(injectedAdStream, "a genuine named NTFS ADS was injected");
            Check(!File.Exists(adsInjectionDestination),
                "ADS injection never publishes the restored destination");
            Check(!Directory.EnumerateDirectories(sandbox, ".chomcio-file-restore-*").Any(),
                "ADS injection leaves no staged plaintext file");
            vault.VerifySnapshot(first.SnapshotId);
            Check(true, "original encrypted snapshot is still verifiable after rejection");
            Console.WriteLine("CHOMCIO_NATIVE_SINGLE_RESTORE_ADS_CHECK=PASS");
        }
        else
        {
            Console.WriteLine("CHOMCIO_NATIVE_SINGLE_RESTORE_ADS_SKIP: test volume is not Windows NTFS");
        }

        Check(new FileInfo(Path.Combine(restoreA, "empty.bin")).Length == 0, "empty file restored");
        MustFail(() => vault.RestoreSnapshot(first.SnapshotId, restoreA), "restoring over existing path must fail");
        var second = vault.BackupDirectory(original);
        Check(second.NewChunks == 0 && second.ReusedChunks >= 3, "unchanged backup reuses objects");
        File.WriteAllText(Path.Combine(nested, "żółw.txt"), "new version");
        var third = vault.BackupDirectory(original);
        Check(third.NewChunks >= 1, "modified file adds chunks");
        string restoreB = Path.Combine(sandbox, "restoreB");
        vault.RestoreSnapshot(third.SnapshotId, restoreB);
        Check(File.ReadAllText(Path.Combine(restoreB, "pliki", "żółw.txt")) == "new version", "latest snapshot restores changed file");
        Check(File.ReadAllText(Path.Combine(restoreA, "pliki", "żółw.txt")) != "new version", "old snapshot intact");

        // Single-file recoverability: do not require or expose unrelated snapshot files.
        string singleFile = Path.Combine(sandbox, "rescued-zolw.txt");
        vault.RestoreFile(first.SnapshotId, "pliki/żółw.txt", singleFile);
        Check(File.ReadAllText(singleFile) == string.Concat(Enumerable.Repeat("żółw\n", 300)),
            "single-file recovery selects exact older snapshot version");
        MustFail(() => vault.RestoreFile(first.SnapshotId, "pliki/żółw.txt", singleFile),
            "single-file recovery must never overwrite an existing file");
        Check(File.ReadAllText(singleFile) == string.Concat(Enumerable.Repeat("żółw\n", 300)),
            "single-file no-clobber preserves existing content");
        MustFail(() => vault.RestoreFile(first.SnapshotId, "pliki/Żółw.txt",
            Path.Combine(sandbox, "wrong-case.txt")), "snapshot relative path must match exact case");
        MustFail(() => vault.RestoreFile(first.SnapshotId, "../large.bin",
            Path.Combine(sandbox, "unsafe-name.txt")), "malformed single-file path refused");
        MustFail(() => vault.RestoreFile(first.SnapshotId, "missing.dat",
            Path.Combine(sandbox, "missing.dat")), "unknown snapshot file refused");
        string singleEmpty = Path.Combine(sandbox, "recovered-empty.dat");
        vault.RestoreFile(first.SnapshotId, "empty.bin", singleEmpty);
        Check(new FileInfo(singleEmpty).Length == 0, "single-file empty content verified");
        string singleLarge = Path.Combine(sandbox, "recovered-large.bin");
        vault.RestoreFile(first.SnapshotId, "large.bin", singleLarge);
        Check(File.ReadAllBytes(singleLarge).SequenceEqual(large), "single-file multi-chunk exact");

        // Windows: the final single-file restore must authenticate/rename one
        // retained FILE_OBJECT. Old path-based File.Move could publish a
        // different plaintext file after the preceding disk SHA readback.
        if (OperatingSystem.IsWindows())
        {
            string ownedRestore = Path.Combine(sandbox, "owned-single-restore.bin");
            bool restoreRenameDenied = false;
            bool restoreWriteDenied = false;
            bool restoreParentRenameDenied = false;
            vault.RestoreFileCore(first.SnapshotId, "large.bin", ownedRestore,
                beforeStageReadback: null,
                whileOwnedRestoreHandlePinned: stage =>
                {
                    try { File.Move(stage, stage + ".alien"); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    { restoreRenameDenied = true; }
                    try { File.WriteAllBytes(stage, new byte[] { 0xEF }); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    { restoreWriteDenied = true; }
                    string directory = Path.GetDirectoryName(stage)!;
                    try { Directory.Move(directory, directory + ".alien"); }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    { restoreParentRenameDenied = true; }
                });
            Check(restoreRenameDenied && restoreWriteDenied && restoreParentRenameDenied,
                "retained owned plaintext and stage parent reject late mutation/renames");
            Check(File.ReadAllBytes(ownedRestore).SequenceEqual(large),
                "handle-bound single-file restore publishes exact original bytes");
            string collisionDestination = Path.Combine(sandbox, "owned-single-collision.bin");
            byte[] preservedCollision = "must-not-be-clobbered"u8.ToArray();
            bool collisionCreated = false;
            MustFail(() => vault.RestoreFileCore(first.SnapshotId, "large.bin",
                collisionDestination, beforeStageReadback: null,
                whileOwnedRestoreHandlePinned: _ =>
                {
                    File.WriteAllBytes(collisionDestination, preservedCollision);
                    collisionCreated = true;
                }), "late single-file destination collision refuses no-replace commit");
            Check(collisionCreated &&
                File.ReadAllBytes(collisionDestination).SequenceEqual(preservedCollision),
                "late restore collision does not overwrite the newly existing file");
            Check(!Directory.EnumerateDirectories(sandbox, ".chomcio-file-restore-*").Any(),
                "failed owned single-file restore cleans only its private stage");
            Console.WriteLine("CHOMCIO_NATIVE_HANDLE_BOUND_SINGLE_RESTORE=PASS");
            // Same-byte substitution at the formerly unguarded boundary:
            // the original exclusive payload writer is CLOSED before the
            // beforeStageReadback callback, and the replacement file contains
            // exactly the authenticated plaintext. Hash-only publication would
            // adopt the FOREIGN FILE_OBJECT. Original writer FileId must win.
            string alienRestore = Path.Combine(sandbox, "owned-single-foreign-identity.bin");
            string relocatedOriginal = Path.Combine(sandbox, "original-restore-writer.bin");
            string? foreignStage = null;
            byte[]? stageWitness = null;
            bool substitutedStage = false;
            MustFail(() => vault.RestoreFileCore(first.SnapshotId, "large.bin",
                alienRestore, beforeStageReadback: path =>
                {
                    stageWitness = File.ReadAllBytes(path);
                    File.Move(path, relocatedOriginal);
                    File.WriteAllBytes(path, stageWitness); // byte-identical foreign file
                    foreignStage = path;
                    substitutedStage = true;
                }), "same-byte foreign plaintext cannot be published by hash alone");
            Check(substitutedStage && foreignStage is not null && stageWitness is not null,
                "native foreign stage substitution reached original writer close boundary");
            Check(!File.Exists(alienRestore),
                "byte-identical foreign stage never becomes user-visible restore");
            Check(File.Exists(relocatedOriginal) &&
                File.ReadAllBytes(relocatedOriginal).SequenceEqual(stageWitness!),
                "the moved ORIGINAL writer-owned plaintext remains untouched");
            Check(File.Exists(foreignStage!) &&
                File.ReadAllBytes(foreignStage!).SequenceEqual(stageWitness!),
                "the substituted FOREIGN plaintext is preserved, not deleted by cleanup");
            Console.WriteLine("CHOMCIO_NATIVE_CREATOR_BOUND_PLAINTEXT_PUBLISH=PASS");
            // Full-directory restore previously authenticated BYTES only.
            // After the original staged child writer closes, move its original
            // FILE_OBJECT away and insert a byte-identical FOREIGN child.
            // The root directory remains original, so root-only FileId checks
            // cannot catch this substitution; child inventory MUST reject it.
            string swappedTreeOutput = Path.Combine(sandbox, "foreign-tree-restore-destination");
            string relocatedTreeOriginal = Path.Combine(sandbox, "tree-original-child-moved.bin");
            string? swappedTreeForeign = null;
            byte[]? treeOriginalBytes = null;
            bool treeSwapObserved = false;
            MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, swappedTreeOutput,
                beforeStageReadback: privateRoot =>
                {
                    string targetChild = Path.Combine(privateRoot, "pliki", "żółw.txt");
                    treeOriginalBytes = File.ReadAllBytes(targetChild);
                    File.Move(targetChild, relocatedTreeOriginal);
                    File.WriteAllBytes(targetChild, treeOriginalBytes); // identical FOREIGN file
                    swappedTreeForeign = targetChild;
                    treeSwapObserved = true;
                }), "identical foreign leaf must not be published in full restored tree");
            Check(treeSwapObserved && !Directory.Exists(swappedTreeOutput),
                "staged child substitution blocked before entire tree visibility");
            Check(treeOriginalBytes is not null && swappedTreeForeign is not null &&
                File.ReadAllBytes(relocatedTreeOriginal).SequenceEqual(treeOriginalBytes) &&
                File.ReadAllBytes(swappedTreeForeign).SequenceEqual(treeOriginalBytes),
                "foreign replacement and moved original child survive fail-closed cleanup");
            Console.WriteLine("CHOMCIO_NATIVE_CREATOR_BOUND_TREE_LEAVES=PASS");
            // New-name injection is not a FileId substitution: every recorded
            // original remains intact, but a FOREIGN extra leaf would appear
            // under a published restore unless we reject unexpected names.
            string extraTreeOutput = Path.Combine(sandbox, "untracked-tree-output");
            string? injectedTreeLeaf = null;
            byte[] injectedTreeBytes = "foreign restore-stage child must survive"u8.ToArray();
            MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, extraTreeOutput,
                beforeStageReadback: null,
                beforePublication: stageRoot =>
                {
                    injectedTreeLeaf = Path.Combine(stageRoot, "injected-untracked-file.bin");
                    File.WriteAllBytes(injectedTreeLeaf, injectedTreeBytes);
                }), "untracked late plaintext child must be rejected before root rename");
            Check(!Directory.Exists(extraTreeOutput) && injectedTreeLeaf is not null &&
                File.ReadAllBytes(injectedTreeLeaf).SequenceEqual(injectedTreeBytes),
                "untracked foreign plaintext retained in private stage, not published or deleted");
            Console.WriteLine("CHOMCIO_NATIVE_NO_UNTRACKED_RESTORE_STAGE_ENTRIES=PASS");
            // Existing original staged inode and names can remain VALID while
            // its contents are modified in place AFTER first full SHA readback.
            // Never publish the original handle with late, unauthenticated bytes.
            string lateTamperRestore = Path.Combine(sandbox, "late-content-tamper-restore");
            bool restoreMutatedOriginal = false;
            MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, lateTamperRestore,
                beforeStageReadback: null, beforePublication: stageRoot =>
                {
                    string originalLeaf = Path.Combine(stageRoot, "pliki", "żółw.txt");
                    using var writer = new FileStream(originalLeaf, FileMode.Open,
                        FileAccess.ReadWrite, FileShare.None);
                    int before = writer.ReadByte();
                    Check(before >= 0, "test source must have nonempty restored leaf");
                    writer.Position = 0;
                    writer.WriteByte((byte)(before ^ 0x40));
                    writer.Flush(flushToDisk: true);
                    restoreMutatedOriginal = true;
                }), "late in-place mutation of ORIGINAL restored leaf must fail authentication");
            Check(restoreMutatedOriginal && !Directory.Exists(lateTamperRestore),
                "in-place mutated original restored file is never published");
            Console.WriteLine("CHOMCIO_NATIVE_LATE_STAGE_RESTORE_CONTENT_REVERIFY=PASS");
            // An ordinary Windows writer must be unable to obtain WRITE access
            // once the ORIGINAL staged leaf read leases are held. Its source
            // name and bytes stay original until owned directory publication.
            string leasedRestore = Path.Combine(sandbox, "immutable-leaf-leased-restore");
            bool restoreWriteDeniedUnderLease = false;
            vault.RestoreSnapshotCore(first.SnapshotId, leasedRestore,
                beforeStageReadback: null, whileContentLeased: stagedRoot =>
                {
                    string originalLeaf = Path.Combine(stagedRoot, "pliki", "żółw.txt");
                    try
                    {
                        using var attacker = new FileStream(originalLeaf, FileMode.Open,
                            FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    }
                    catch (IOException) { restoreWriteDeniedUnderLease = true; }
                });
            Check(restoreWriteDeniedUnderLease && Directory.Exists(leasedRestore),
                "restore refuses concurrent writer, yet root rename succeeds under leaf leases");
            Console.WriteLine("CHOMCIO_NATIVE_IMMUTABLE_RESTORE_LEAF_LEASE=PASS");

        }

        // Self-contained encrypted export, independent of original vault.
        string portable = Path.Combine(sandbox, "encrypted-portable");
        vault.ExportEncryptedSnapshot(first.SnapshotId, portable);
        Check(File.Exists(Path.Combine(portable, "repo.json")), "portable export contains config");
        if (OperatingSystem.IsWindows())
        {
            // Exported AES-GCM records also require creation-time FILE_OBJECT
            // identities. Identical ciphertext from a different file must NOT
            // be adopted merely because VerifySnapshot authenticates it.
            string replacedExport = Path.Combine(sandbox, "foreign-encrypted-export-destination");
            string originalExportConfig = Path.Combine(sandbox, "original-export-config-moved.json");
            string? foreignExportConfig = null;
            byte[]? expectedExportConfig = null;
            bool exportSwapObserved = false;
            MustFail(() => vault.ExportEncryptedSnapshotCore(first.SnapshotId, replacedExport,
                afterPublished: null, beforePublication: privateRoot =>
                {
                    string stagedConfig = Path.Combine(privateRoot, "repo.json");
                    expectedExportConfig = File.ReadAllBytes(stagedConfig);
                    File.Move(stagedConfig, originalExportConfig);
                    File.WriteAllBytes(stagedConfig, expectedExportConfig); // same bytes, new ID
                    foreignExportConfig = stagedConfig;
                    exportSwapObserved = true;
                }), "foreign same-byte encrypted export record must not be published");
            Check(exportSwapObserved && !Directory.Exists(replacedExport),
                "substituted export config record refused before root publication");
            Check(expectedExportConfig is not null && foreignExportConfig is not null &&
                File.ReadAllBytes(originalExportConfig).SequenceEqual(expectedExportConfig) &&
                File.ReadAllBytes(foreignExportConfig).SequenceEqual(expectedExportConfig),
                "foreign encrypted config and moved original both preserved");
            Console.WriteLine("CHOMCIO_NATIVE_CREATOR_BOUND_PORTABLE_EXPORT_LEAVES=PASS");
            string extraExportDestination = Path.Combine(sandbox, "untracked-export-output");
            string? injectedExportLeaf = null;
            byte[] injectedExportBytes = "foreign portable export child must survive"u8.ToArray();
            MustFail(() => vault.ExportEncryptedSnapshotCore(first.SnapshotId,
                extraExportDestination, afterPublished: null, beforePublication: stageRoot =>
                {
                    injectedExportLeaf = Path.Combine(stageRoot, "untracked-export-record.bin");
                    File.WriteAllBytes(injectedExportLeaf, injectedExportBytes);
                }), "untracked late encrypted-export child must be rejected before root rename");
            Check(!Directory.Exists(extraExportDestination) && injectedExportLeaf is not null &&
                File.ReadAllBytes(injectedExportLeaf).SequenceEqual(injectedExportBytes),
                "untracked foreign export record retained, not published or deleted");
            Console.WriteLine("CHOMCIO_NATIVE_NO_UNTRACKED_EXPORT_STAGE_ENTRIES=PASS");
            // Tamper an ORIGINAL export chunk using FileMode.Open, not a
            // substituted filename. Its FileId and directory inventory remain
            // unchanged, so identity-only publication must NEVER be enough.
            string lateTamperExport = Path.Combine(sandbox, "late-content-tamper-export");
            bool exportMutatedOriginal = false;
            MustFail(() => vault.ExportEncryptedSnapshotCore(first.SnapshotId,
                lateTamperExport, afterPublished: null, beforePublication: stageRoot =>
                {
                    string originalChunk = Directory.EnumerateFiles(
                        Path.Combine(stageRoot, "objects"), "*.obj", SearchOption.AllDirectories).First();
                    using var writer = new FileStream(originalChunk, FileMode.Open,
                        FileAccess.ReadWrite, FileShare.None);
                    int before = writer.ReadByte();
                    Check(before >= 0, "test export must contain nonempty encrypted record");
                    writer.Position = 0;
                    writer.WriteByte((byte)(before ^ 0x40));
                    writer.Flush(flushToDisk: true);
                    exportMutatedOriginal = true;
                }), "late in-place corruption of ORIGINAL export ciphertext must fail authentication");
            Check(exportMutatedOriginal && !Directory.Exists(lateTamperExport),
                "in-place mutated original export file is never published");
            Console.WriteLine("CHOMCIO_NATIVE_LATE_STAGE_EXPORT_CONTENT_REVERIFY=PASS");
            string leasedExport = Path.Combine(sandbox, "immutable-leaf-leased-export");
            bool exportWriteDeniedUnderLease = false;
            vault.ExportEncryptedSnapshotCore(first.SnapshotId, leasedExport,
                afterPublished: null, whileContentLeased: stagedRoot =>
                {
                    string originalRecord = Path.Combine(stagedRoot, "repo.json");
                    try
                    {
                        using var attacker = new FileStream(originalRecord, FileMode.Open,
                            FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    }
                    catch (IOException) { exportWriteDeniedUnderLease = true; }
                });
            Check(exportWriteDeniedUnderLease && File.Exists(Path.Combine(leasedExport, "repo.json")),
                "encrypted export refuses concurrent writer, still publishes original directory");
            Console.WriteLine("CHOMCIO_NATIVE_IMMUTABLE_EXPORT_LEAF_LEASE=PASS");

            // Real Windows C# cancellation DURING a multi-block encrypted
            // portable-object write, not merely before starting an export.
            // Cancellation must abort publication, remove only the original
            // private staged records and leave the encrypted source intact.
            string cancelledPortable = Path.Combine(sandbox, "mid-record-cancelled-export");
            string? cancelledPrivateRoot = null;
            bool cancelledInSecondBlock = false;
            using (var exportStop = new CancellationTokenSource())
            {
                MustCancel(() => vault.ExportEncryptedSnapshotCore(first.SnapshotId,
                    cancelledPortable, afterPublished: null,
                    cancellationToken: exportStop.Token,
                    afterPrivateRecordBlock: (recordPath, blockNumber) =>
                    {
                        if (recordPath.EndsWith(".obj", StringComparison.OrdinalIgnoreCase) &&
                            blockNumber == 2)
                        {
                            cancelledPrivateRoot = Directory.GetParent(recordPath)!.Parent!.Parent!.FullName;
                            cancelledInSecondBlock = true;
                            exportStop.Cancel();
                        }
                    }), "cancelling a multi-block encrypted export must abort the commit");
            }
            Check(cancelledInSecondBlock && cancelledPrivateRoot is not null,
                "native export actually cancelled DURING a multi-block ciphertext record");
            Check(!Directory.Exists(cancelledPortable) &&
                !Directory.Exists(cancelledPrivateRoot!),
                "mid-record cancellation did not publish or retain owned private ciphertext");
            vault.VerifySnapshot(first.SnapshotId);
            Console.WriteLine("CHOMCIO_NATIVE_MID_RECORD_EXPORT_CANCEL_CLEANUP=PASS");
        }
        Check(Directory.GetFiles(Path.Combine(portable, "snapshots"), "*.snap").Length == 1,
            "portable export contains exactly one snapshot");
        // Portable import/export used to repeat a length check + File.ReadAllBytes
        // path resolution. Bound every opened record (config, object, manifest)
        // to avoid an unbounded allocation if portable media changes mid-read.
        string portableConfigPath = Path.Combine(portable, "repo.json");
        string portableSnapshotPath = Path.Combine(portable, "snapshots", first.SnapshotId + ".snap");
        string portableObjectPath = Directory.EnumerateFiles(Path.Combine(portable, "objects"),
            "*.obj", SearchOption.AllDirectories).First();
        foreach (var pair in new[]
        {
            (Path: portableConfigPath, Limit: 16_384),
            (Path: portableSnapshotPath, Limit: 64 * 1024 * 1024 + 36),
            (Path: portableObjectPath, Limit: LocalEncryptedVault.ChunkBytes + 36)
        })
        {
            byte[] existing = File.ReadAllBytes(pair.Path); // Test fixture only.
            Check(LocalEncryptedVault.ReadBoundedFile(pair.Path, pair.Limit).SequenceEqual(existing),
                "portable record bounded read-back matches actual bytes: " + pair.Path);
            MustFail(() => LocalEncryptedVault.ReadBoundedFile(pair.Path, existing.Length - 1),
                "portable record rejects a too-small read limit");
        }
        Console.WriteLine("CHOMCIO_NATIVE_BOUNDED_PORTABLE_IO=PASS");
        using (var imported = LocalEncryptedVault.Open(portable, password))
        {
            imported.VerifySnapshot(first.SnapshotId);
            Check(imported.ReadSnapshot(first.SnapshotId).Directories?.Contains("empty-parent/empty-leaf") == true,
                "portable export preserves empty directory manifest");
            string portableRestore = Path.Combine(sandbox, "portable-restore");
            imported.RestoreSnapshot(first.SnapshotId, portableRestore);
            Check(Directory.Exists(Path.Combine(portableRestore, "empty-parent", "empty-leaf")),
                "portable restore recovers nested empty directories");
            Check(File.ReadAllBytes(Path.Combine(portableRestore, "large.bin")).SequenceEqual(large),
                "portable export independently restores multichunk content");
            Check(File.ReadAllText(Path.Combine(portableRestore, "pliki", "żółw.txt")) ==
                string.Concat(Enumerable.Repeat("żółw\n", 300)),
                "portable export preserves old version");
        }
        // The first offline cloud-download primitive: import a signed portable
        // recovery point into a SEPARATE instance of the original repository
        // lineage. The source vault is untouched, and publication is manifest-last.
        string importedRoot = Path.Combine(sandbox, "imported-original-lineage");
        Directory.CreateDirectory(importedRoot);
        Directory.CreateDirectory(Path.Combine(importedRoot, "objects"));
        Directory.CreateDirectory(Path.Combine(importedRoot, "snapshots"));
        File.Copy(Path.Combine(repo, "repo.json"), Path.Combine(importedRoot, "repo.json"));
        using (var importer = LocalEncryptedVault.Open(importedRoot, password))
        {
            importer.ImportEncryptedSnapshot(first.SnapshotId, portable);
            Check(importer.ListSnapshotIds().SequenceEqual(new[] { first.SnapshotId }),
                "import publishes exactly the selected recovery point");
            importer.VerifySnapshot(first.SnapshotId);
            string importedRestored = Path.Combine(sandbox, "restored-from-import");
            importer.RestoreSnapshot(first.SnapshotId, importedRestored);
            Check(File.ReadAllBytes(Path.Combine(importedRestored, "large.bin")).SequenceEqual(large),
                "imported multichunk snapshot restores exact bytes");
            Check(Directory.Exists(Path.Combine(importedRestored, "empty-parent", "empty-leaf")),
                "imported v2 snapshot restores empty folders");
            byte[] manifestBefore = File.ReadAllBytes(Path.Combine(importedRoot, "snapshots",
                first.SnapshotId + ".snap"));
            importer.ImportEncryptedSnapshot(first.SnapshotId, portable);
            Check(File.ReadAllBytes(Path.Combine(importedRoot, "snapshots",
                first.SnapshotId + ".snap")).SequenceEqual(manifestBefore),
                "idempotent import preserves existing snapshot ciphertext");
            MustFail(() => importer.ImportEncryptedSnapshot(first.SnapshotId, importedRoot),
                "import rejects source and destination overlap");
        }
        string differentRepo = Path.Combine(sandbox, "unrelated-repository");
        LocalEncryptedVault.Initialize(differentRepo, password);
        using (var unrelated = LocalEncryptedVault.Open(differentRepo, password))
        {
            MustFail(() => unrelated.ImportEncryptedSnapshot(first.SnapshotId, portable),
                "same password does not authorize import into a different vault lineage");
            Check(unrelated.ListSnapshotIds().Count == 0, "foreign import does not publish a snapshot");
        }
        // Native adversarial import: the source chunk is modified AFTER the
        // initial authenticated portable preflight, BEFORE its separate copy.
        // No poisoned object or visible snapshot may enter the destination.
        string preflightSwapPortable = Path.Combine(sandbox, "preflight-swap-portable");
        vault.ExportEncryptedSnapshot(first.SnapshotId, preflightSwapPortable);
        string firstImportedId = vault.ReadSnapshot(first.SnapshotId).Files
            .SelectMany(file => file.Chunks).Distinct(StringComparer.Ordinal).First();
        string firstImportedObject = Path.Combine(preflightSwapPortable, "objects",
            firstImportedId[..2], firstImportedId + ".obj");
        string preflightSwapTarget = Path.Combine(sandbox, "preflight-swap-target");
        Directory.CreateDirectory(preflightSwapTarget);
        Directory.CreateDirectory(Path.Combine(preflightSwapTarget, "objects"));
        Directory.CreateDirectory(Path.Combine(preflightSwapTarget, "snapshots"));
        File.Copy(Path.Combine(repo, "repo.json"), Path.Combine(preflightSwapTarget, "repo.json"));
        bool preflightMutationWasInjected = false;
        using (var importer = LocalEncryptedVault.Open(preflightSwapTarget, password))
        {
            MustFail(() => importer.ImportEncryptedSnapshotCore(first.SnapshotId, preflightSwapPortable,
                afterPortablePreflight: () =>
                {
                    byte[] mutated = File.ReadAllBytes(firstImportedObject);
                    mutated[^1] ^= 0x80;
                    File.WriteAllBytes(firstImportedObject, mutated);
                    preflightMutationWasInjected = true;
                }), "late changed encrypted import source must not poison target object store");
            Check(preflightMutationWasInjected, "late source mutation really occurred after preflight");
            Check(!Directory.EnumerateFiles(Path.Combine(preflightSwapTarget, "objects"),
                    "*.obj", SearchOption.AllDirectories).Any(),
                "late tampered source did not leave a poisoned destination object");
            Check(importer.ListSnapshotIds().Count == 0,
                "late tampered import did not publish an unreadable recovery point");
        }
        Check(File.Exists(firstImportedObject), "import never deleted modified foreign portable source");
        Console.WriteLine("CHOMCIO_NATIVE_IMPORT_CAPTURED_CIPHERTEXT_AUTH=PASS");
        // The FIRST decrypted import target chunk escaped zeroization if a
        // SECOND portable-source read failed before the old try/finally began.
        // Mutate only a disposable export after the destination chunk has been
        // authenticated. Assert that the EXACT escaped array is wiped, while
        // source corruption prevents publishing the snapshot manifest.
        string secondReadPortable = Path.Combine(sandbox, "import-second-read-portable");
        vault.ExportEncryptedSnapshot(first.SnapshotId, secondReadPortable);
        string secondReadTarget = Path.Combine(sandbox, "import-second-read-target");
        Directory.CreateDirectory(secondReadTarget);
        Directory.CreateDirectory(Path.Combine(secondReadTarget, "objects"));
        Directory.CreateDirectory(Path.Combine(secondReadTarget, "snapshots"));
        File.Copy(Path.Combine(repo, "repo.json"), Path.Combine(secondReadTarget, "repo.json"));
        string secondReadRecord = Path.Combine(secondReadPortable, "objects",
            firstImportedId[..2], firstImportedId + ".obj");
        byte[]? escapedTargetPlaintext = null;
        bool secondReadTamperInjected = false;
        using (var secondReadImporter = LocalEncryptedVault.Open(secondReadTarget, password))
        {
            MustFail(() => secondReadImporter.ImportEncryptedSnapshotCore(first.SnapshotId,
                secondReadPortable, afterPortablePreflight: null,
                afterImportedTargetChunkRead: plaintext =>
                {
                    if (secondReadTamperInjected) return;
                    Check(plaintext.Length > 0 && plaintext.Any(value => value != 0),
                        "second-read fixture captures genuine nonempty authenticated plaintext");
                    escapedTargetPlaintext = plaintext;
                    byte[] changed = File.ReadAllBytes(secondReadRecord);
                    changed[^1] ^= 0x40; // GCM tag/ciphertext corruption, same file object
                    File.WriteAllBytes(secondReadRecord, changed);
                    secondReadTamperInjected = true;
                }), "portable read failure after target decrypt must refuse import");
            Check(secondReadTamperInjected && escapedTargetPlaintext is not null,
                "portable bytes really changed AFTER capturing target plaintext");
            Check(escapedTargetPlaintext is not null && escapedTargetPlaintext.All(value => value == 0),
                "failure of the SECOND read zeroizes the FIRST returned plaintext buffer");
            Check(secondReadImporter.ListSnapshotIds().Count == 0,
                "failed second portable authentication never publishes manifest");
        }
        Console.WriteLine("CHOMCIO_NATIVE_IMPORT_SECOND_READ_ZEROIZATION=PASS");
        // Cancel AFTER one verified immutable import chunk. Previously import
        // had no CancellationToken and would continue copying multi-GB data
        // and publish the snapshot despite the GUI/CLI STOP request.
        // Work only in disposable same-lineage vaults; immutable unreferenced
        // chunk(s) may remain after STOP, but no snapshot manifest may appear.
        string interruptedImportRoot = Path.Combine(sandbox, "mid-import-stop-target");
        Directory.CreateDirectory(interruptedImportRoot);
        Directory.CreateDirectory(Path.Combine(interruptedImportRoot, "objects"));
        Directory.CreateDirectory(Path.Combine(interruptedImportRoot, "snapshots"));
        File.Copy(Path.Combine(repo, "repo.json"), Path.Combine(interruptedImportRoot, "repo.json"));
        using (var interruptedImporter = LocalEncryptedVault.Open(interruptedImportRoot, password))
        using (var stopImport = new CancellationTokenSource())
        {
            int verifiedObjectCountBeforeStop = 0;
            MustCancel(() => interruptedImporter.ImportEncryptedSnapshotCore(first.SnapshotId, portable,
                afterPortablePreflight: null, cancellationToken: stopImport.Token,
                afterVerifiedObject: count =>
                {
                    verifiedObjectCountBeforeStop = count;
                    stopImport.Cancel();
                }), "mid-import STOP must interrupt before snapshot manifest publication");
            Check(verifiedObjectCountBeforeStop == 1,
                "native fixture canceled exactly after first authenticated imported object");
            Check(interruptedImporter.ListSnapshotIds().Count == 0,
                "mid-import STOP never advertises an incomplete recovery point");
            Check(Directory.EnumerateFiles(Path.Combine(interruptedImportRoot, "objects"),
                    "*.obj", SearchOption.AllDirectories).Count() == 1,
                "already-verified immutable imported chunk survives STOP for safe retry");
            interruptedImporter.ImportEncryptedSnapshot(first.SnapshotId, portable);
            interruptedImporter.VerifySnapshot(first.SnapshotId);
            Check(interruptedImporter.ListSnapshotIds().SequenceEqual(new[] { first.SnapshotId }),
                "import resumes safely and publishes exactly one verified recovery point");
        }
        // A STOP requested immediately after source preflight must create NO
        // new destination objects or snapshot; no unsafe path deletion.
        string stoppedPreflightImportRoot = Path.Combine(sandbox, "preflight-stop-target");
        Directory.CreateDirectory(stoppedPreflightImportRoot);
        Directory.CreateDirectory(Path.Combine(stoppedPreflightImportRoot, "objects"));
        Directory.CreateDirectory(Path.Combine(stoppedPreflightImportRoot, "snapshots"));
        File.Copy(Path.Combine(repo, "repo.json"), Path.Combine(stoppedPreflightImportRoot, "repo.json"));
        using (var preflightImporter = LocalEncryptedVault.Open(stoppedPreflightImportRoot, password))
        using (var stopPreflightImport = new CancellationTokenSource())
        {
            MustCancel(() => preflightImporter.ImportEncryptedSnapshotCore(first.SnapshotId, portable,
                afterPortablePreflight: () => stopPreflightImport.Cancel(),
                cancellationToken: stopPreflightImport.Token),
                "STOP immediately after portable source authentication must block all imports");
            Check(!Directory.EnumerateFiles(Path.Combine(stoppedPreflightImportRoot, "objects"),
                    "*.obj", SearchOption.AllDirectories).Any(),
                "preflight STOP never created target ciphertext chunks");
            Check(preflightImporter.ListSnapshotIds().Count == 0,
                "preflight STOP never created visible manifest");
        }
        Console.WriteLine("CHOMCIO_NATIVE_IMPORT_CANCELLATION=PASS");

        string corruptedPortable = Path.Combine(sandbox, "corrupted-portable");
        vault.ExportEncryptedSnapshot(first.SnapshotId, corruptedPortable);
        string importChunk = Directory.EnumerateFiles(Path.Combine(corruptedPortable, "objects"),
            "*.obj", SearchOption.AllDirectories).First();
        byte[] corruptedBytes = File.ReadAllBytes(importChunk);
        corruptedBytes[^1] ^= 1;
        File.WriteAllBytes(importChunk, corruptedBytes);
        string rejectRoot = Path.Combine(sandbox, "reject-import-repository");
        Directory.CreateDirectory(rejectRoot);
        Directory.CreateDirectory(Path.Combine(rejectRoot, "objects"));
        Directory.CreateDirectory(Path.Combine(rejectRoot, "snapshots"));
        File.Copy(Path.Combine(repo, "repo.json"), Path.Combine(rejectRoot, "repo.json"));
        using (var rejectVault = LocalEncryptedVault.Open(rejectRoot, password))
        {
            MustFail(() => rejectVault.ImportEncryptedSnapshot(first.SnapshotId, corruptedPortable),
                "corrupt portable ciphertext rejected before import publishes data");
            Check(rejectVault.ListSnapshotIds().Count == 0,
                "tampered encrypted export never creates a visible recovery point");
        }
        MustFail(() => vault.ExportEncryptedSnapshot(first.SnapshotId, portable),
            "export must refuse overwrite of existing portable vault");
        MustFail(() => vault.ExportEncryptedSnapshot(first.SnapshotId,
            Path.Combine(repo, "nested-export")), "export must reject vault overlap");

        string corruptPreflightParent=Path.Combine(sandbox,"corrupt-preflight");Directory.CreateDirectory(corruptPreflightParent);
        // Flip an authenticated ciphertext bit: complete restore must fail without exposing a target folder.
        var chunkId = vault.ReadSnapshot(first.SnapshotId).Files
            .Single(f => f.Path == "large.bin").Chunks[0];
        string chunkFile = Path.Combine(repo, "objects", chunkId[..2], chunkId + ".obj");
        byte[] encrypted = File.ReadAllBytes(chunkFile);
        encrypted[^1] ^= 1;
        File.WriteAllBytes(chunkFile, encrypted);
        string failedReadbackPoint = Guid.NewGuid().ToString("N");
        MustFail(() => vault.PublishVerifiedSnapshot(failedReadbackPoint, firstManifest, () => { }),
            "corrupt stored ciphertext prevents a NEW snapshot from being published");
        Check(!File.Exists(Path.Combine(repo, "snapshots", failedReadbackPoint + ".snap")),
            "read-back failure did not publish a recovery point");
        MustFail(() => vault.VerifySnapshot(first.SnapshotId), "ciphertext tamper rejected");
        string corruptExport = Path.Combine(corruptPreflightParent, "corrupt-export");
        MustFail(() => vault.ExportEncryptedSnapshot(first.SnapshotId, corruptExport),
            "export rejects corrupt encrypted object");
        Check(!Directory.Exists(corruptExport), "corrupt export never published");
        Check(!Directory.EnumerateDirectories(corruptPreflightParent, ".chomcio-export-*").Any(),
            "failed portable export stage cleaned");
        string restoreBad = Path.Combine(corruptPreflightParent, "should-not-exist");
        bool wholeRestoreStageRequested = false;
        MustFail(() => vault.RestoreSnapshotCore(first.SnapshotId, restoreBad,
            beforeStageReadback: null,
            beforePrivateStageCreation: () => wholeRestoreStageRequested = true),
            "corrupt restore rejected before creating a plaintext stage");
        Check(!wholeRestoreStageRequested,
            "whole-folder corrupt ciphertext rejected before creating any plaintext stage");
        string fileBad = Path.Combine(corruptPreflightParent, "corrupted-file.bin");
        bool singleRestoreStageRequested = false;
        MustFail(() => vault.RestoreFileCore(first.SnapshotId, "large.bin", fileBad,
            beforeStageReadback: null,
            beforePrivateStageCreation: () => singleRestoreStageRequested = true),
            "corrupt selected-file restore rejected before creating a plaintext stage");
        Check(!singleRestoreStageRequested,
            "single-file corrupt ciphertext rejected before creating any plaintext stage");
        // Test the unchanged PUBLIC entrypoints as well as the internal
        // stage-observer overload used for the preflight ordering assertion.
        MustFail(() => vault.RestoreSnapshot(first.SnapshotId, restoreBad),
            "public folder restore rejects corrupt encrypted object");
        MustFail(() => vault.RestoreFile(first.SnapshotId, "large.bin", fileBad),
            "public selected-file restore rejects corrupt encrypted object");
        Console.WriteLine("CHOMCIO_NATIVE_RESTORE_PREFLIGHT=PASS");
        Check(!File.Exists(fileBad), "corrupt single file never published");
        Check(!Directory.EnumerateDirectories(corruptPreflightParent, ".chomcio-file-restore-*").Any(),
            "failed single-file stage cleaned");
        Check(!Directory.Exists(restoreBad), "corrupt restore target never published");
        Check(!Directory.EnumerateDirectories(corruptPreflightParent, ".chomcio-restore-*").Any(), "failed stage cleaned");
        // Read cancellation BEFORE AEAD/JSON must interrupt a genuine large
        // encrypted manifest, not merely a synthetic in-memory stream.
        // This fixture stores ONLY 1,500 logical empty entries in an isolated
        // disposable vault; it does not create or modify any user files.
        string largeMetadataId = Guid.NewGuid().ToString("N");
        string emptyDigest = Convert.ToHexString(SHA256.HashData(Array.Empty<byte>())).ToLowerInvariant();
        var metadataEntries = Enumerable.Range(0, 1500)
            .Select(i => new LocalEncryptedVault.FileEntry(
                "manifest/empty-" + i.ToString("D5") + ".txt", 0, emptyDigest, new List<string>()))
            .ToList();
        var largeMetadataSnapshot = new LocalEncryptedVault.Snapshot(2,
            DateTimeOffset.UtcNow, metadataEntries, new List<string> { "manifest" });
        vault.PublishVerifiedSnapshot(largeMetadataId, largeMetadataSnapshot, () => { });
        string metadataRecord = Path.Combine(repo, "snapshots", largeMetadataId + ".snap");
        Check(new FileInfo(metadataRecord).Length > 3 * 65_536,
            "native cancellation fixture is a real >3-block encrypted manifest");
        byte[] originalMetadataDigest = SHA256.HashData(File.ReadAllBytes(metadataRecord));
        using (var stopMetadataRead = new CancellationTokenSource())
        {
            int lastReadOffset = 0;
            MustCancel(() => vault.ReadSnapshotCore(largeMetadataId, stopMetadataRead.Token,
                afterManifestReadBlock: offset =>
                {
                    lastReadOffset = offset;
                    if (offset >= 2 * 65_536) stopMetadataRead.Cancel();
                }), "mid-record STOP must interrupt actual nofollow manifest input");
            Check(lastReadOffset == 2 * 65_536,
                "STOP rejected the partial ciphertext after exactly two 64 KiB blocks");
        }
        Check(CryptographicOperations.FixedTimeEquals(
                originalMetadataDigest, SHA256.HashData(File.ReadAllBytes(metadataRecord))),
            "cancelled read never changes the already-published encrypted manifest");
        Check(vault.ReadSnapshot(largeMetadataId).Files.Count == 1500,
            "original genuine encrypted manifest still decodes exactly after cancel");
        Console.WriteLine("CHOMCIO_NATIVE_CANCELLABLE_MANIFEST_READ=PASS");

        MustFail(() => vault.ReadSnapshot("../not-an-id"), "snapshot path traversal rejected");
    }
    // Cross-language fixture was created by the independent Python AES-GCM reference.
    // This test MUST execute on native .NET before claiming C# format interoperability.
    string fixtures = Path.Combine(AppContext.BaseDirectory, "fixtures");
    string fixtureRepo = Path.Combine(fixtures, "reference_v1_vault");
    string fixtureSpecPath = Path.Combine(fixtures, "reference_v1_expected.json");
    if (!File.Exists(fixtureSpecPath)) throw new Exception("Missing cross-language encrypted fixture.");
    using (var fixture = System.Text.Json.JsonDocument.Parse(File.ReadAllText(fixtureSpecPath)))
    {
        string id = fixture.RootElement.GetProperty("SnapshotId").GetString()!;
        string fixturePassword = fixture.RootElement.GetProperty("PasswordTestOnly").GetString()!;
        using var external = LocalEncryptedVault.Open(fixtureRepo, fixturePassword);
        external.VerifySnapshot(id);
        Check(external.ReadSnapshot(id).Version == 1,
            "legacy v1 encrypted fixture remains readable");
        string crossRestore = Path.Combine(sandbox, "from-python-fixture");
        external.RestoreSnapshot(id, crossRestore);
        foreach (var file in fixture.RootElement.GetProperty("Files").EnumerateObject())
        {
            string filePath = Path.Combine(crossRestore, file.Name.Replace('/', Path.DirectorySeparatorChar));
            Check(File.Exists(filePath), "C# restored Python file " + file.Name);
            string actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(filePath))).ToLowerInvariant();
            Check(actual == file.Value.GetString(), "C# interoperable fixture SHA-256 " + file.Name);
            string selectedDestination = Path.Combine(sandbox, "selected-fixture-" + Guid.NewGuid().ToString("N"));
            external.RestoreFile(id, file.Name, selectedDestination);
            string selectedDigest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(selectedDestination)))
                .ToLowerInvariant();
            Check(selectedDigest == file.Value.GetString(),
                "C# interoperable selected-file fixture SHA-256 " + file.Name);
        }
    }
    Console.WriteLine($"CHOMCIO_NATIVE_SYMLINK_CHECKS_EXECUTED={nativeLinkChecksExecuted}/5");
    Console.WriteLine($"CHOMCIO_NATIVE_SMOKE_PASS assertions={assertions}");
    return 0;
}
finally
{
    if (Directory.Exists(sandbox)) Directory.Delete(sandbox, recursive: true);
}

// Production ReadChunk uses the Stream.Read(byte[],int,int) overload.
internal sealed class StopAfterFirstReadStream : MemoryStream
{
    private readonly Action _stop;
    internal int ReadCalls { get; private set; }
    internal int LargestRequest { get; private set; }
    internal StopAfterFirstReadStream(byte[] bytes, Action stop) : base(bytes, writable: false)
    {
        _stop = stop;
    }
    public override int Read(byte[] buffer, int offset, int count)
    {
        ReadCalls++;
        LargestRequest = Math.Max(LargestRequest, count);
        int read = base.Read(buffer, offset, count);
        _stop();
        return read;
    }
}
