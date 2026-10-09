using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SignService.Services;
using SignService.ViewModels;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

// Соподписание: поиск .sig по хешу, явный режим, подтверждения, резервная копия,
// имя результата «Объединить .sig» и проверка ГОСТ с параметрами signatureAlgorithm.
internal static class CoSignTests
{
    private static readonly VerificationOptions Crypto = new()
        { CheckCertificateTrust = false, CheckRevocation = false, UseSystemTrustStore = false };

    public static async Task RunAsync(string tempRoot, DocumentSigner signer)
    {
        var root = Path.Combine(tempRoot, "cosign");
        Directory.CreateDirectory(root);
        using var certA = MakeCert("CN=Подписант А");
        using var certB = MakeCert("CN=Подписант Б");
        using var certC = MakeCert("CN=Подписант В");
        var data = System.Text.Encoding.UTF8.GetBytes("актуальный документ");
        var other = System.Text.Encoding.UTF8.GetBytes("другая версия документа");

        await CheckDiscoveryAndAppend(root, signer, certA, certB, data);
        await CheckBackupOffByDefault(root, signer, certA, certB, data);
        await CheckApplyModeToAll(root, signer, certA, data);
        await CheckCreateNewConfirmation(root, signer, certA, certB, data);
        await CheckExclusionConfirmation(root, signer, certA, certB, certC, data, other);
        await CheckUnmatchedSignatureListed(root, signer, certA, data, other);
        CheckMergeNamesOutput(root, signer, certA, certB, data);
        CheckGostParameters();
        await CheckSamplesIfPresent(root);
        Console.WriteLine("cosign: discovery, confirmation, backup, merge name, GOST parameters: OK");
    }

    private static async Task CheckDiscoveryAndAppend(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "append");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "договор.pdf");
        var odd = Path.Combine(dir, "договор-.pdf .sig");
        await File.WriteAllBytesAsync(document, data);
        var original = signer.Sign(data, certA);
        await File.WriteAllBytesAsync(odd, original);

        var vm = ViewModel(dir);
        vm.AddFiles(odd, document); // подпись раньше документа — всё равно находится по хешу
        var item = vm.Files.Single();
        Assert(item.StatusDisplay.Contains("будет добавлена подпись №2")
            && item.StatusDisplay.Contains("договор-.pdf .sig")
            && item.StatusDisplay.Contains("1 подписант"),
            "plan must name the odd signature and the next signer number: " + item.StatusDisplay);
        Assert(item.SelectedCoSignOption is { CreateNew: false }, "default mode adds to the discovered signature");
        Assert(SignatureDiscovery.SamePath(item.PlannedOutputPath, odd), "output is the discovered file, not a new имя.sig");

        vm.SelectedCertificate = new CertificateItem(certB);
        vm.CreateSignatureBackup = true;
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed, "append sign failed: " + item.Message);
        Assert(item.StatusDisplay.StartsWith("Подписан: 2 (1 + ваша) → договор-.pdf .sig", StringComparison.Ordinal),
            "signed row must show previous count and target: " + item.StatusDisplay);
        Assert(!File.Exists(document + ".sig"), "canonical имя.sig must not appear when appending to the odd file");
        Assert(CmsMerger.CountSigners(await File.ReadAllBytesAsync(odd)) == 2, "odd file must now have 2 signers");
        var backups = Directory.GetFiles(dir, "*.bak");
        Assert(backups.Length == 1 && (await File.ReadAllBytesAsync(backups[0])).SequenceEqual(original),
            "backup must keep the signature bytes from before the append");
        Assert(signer.VerifyDetached(data, await File.ReadAllBytesAsync(odd)), "appended signature must verify");
        Console.WriteLine("cosign: odd name discovered by hash, append shows «2 (1 + ваша)», backup kept: OK");
    }

    private static async Task CheckBackupOffByDefault(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        Assert(!new AppSettings().CreateSignatureBackup, "backup setting must default to off");
        var dir = Path.Combine(root, "no_backup");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "акт.pdf");
        var odd = Path.Combine(dir, "акт-.pdf .sig");
        await File.WriteAllBytesAsync(document, data);
        await File.WriteAllBytesAsync(odd, signer.Sign(data, certA));

        var vm = ViewModel(dir);
        vm.AddFiles(document);
        vm.SelectedCertificate = new CertificateItem(certB);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(vm.Files.Single().Status == SignStatus.Signed, "sign without backup failed: " + vm.Files.Single().Message);
        Assert(Directory.GetFiles(dir, "*.bak").Length == 0, "default settings must not create a .bak");
        Assert(CmsMerger.CountSigners(await File.ReadAllBytesAsync(odd)) == 2, "append without backup must still add the signer");
        Console.WriteLine("cosign: backup checkbox defaults off and skips .bak: OK");
    }

    private static async Task CheckApplyModeToAll(string root, DocumentSigner signer, X509Certificate2 certA, byte[] data)
    {
        Assert(!new AppSettings().ApplyCoSignToAll, "apply-to-all must default to off");
        var dir = Path.Combine(root, "apply_all");
        Directory.CreateDirectory(dir);
        var first = Path.Combine(dir, "первый.pdf");
        var second = Path.Combine(dir, "второй.pdf");
        var third = Path.Combine(dir, "третий.pdf");
        var thirdBytes = System.Text.Encoding.UTF8.GetBytes("другой документ для третьего файла");
        await File.WriteAllBytesAsync(first, data);
        await File.WriteAllBytesAsync(second, System.Text.Encoding.UTF8.GetBytes("документ без своей подписи"));
        await File.WriteAllBytesAsync(third, thirdBytes);
        await File.WriteAllBytesAsync(Path.Combine(dir, "первый-.pdf .sig"), signer.Sign(data, certA));
        await File.WriteAllBytesAsync(Path.Combine(dir, "третий-.pdf .sig"), signer.Sign(thirdBytes, certA));

        var vm = ViewModel(dir);
        vm.AddFiles(first, second);
        var lead = vm.Files[0];
        var other = vm.Files[1];
        Assert(lead.SelectedCoSignOption is { CreateNew: false }, "first file has a signature to append to");
        Assert(other.SelectedCoSignOption is { CreateNew: true } && !other.SharedAddUnavailable,
            "without the checkbox a file with no signature just offers a new file");

        vm.ApplyCoSignToAll = true;
        Assert(!other.CoSignChoiceEnabled && other.SharedAddUnavailable
            && other.SelectedCoSignOption is { CreateNew: true }
            && other.WarningDisplay!.Contains("недоступен"),
            "apply-to-all must say when add mode is impossible: " + other.WarningDisplay);
        Assert(lead.CoSignChoiceEnabled, "the first file stays editable");

        lead.SelectedCoSignOption = lead.CoSignOptions.Single(option => option.CreateNew);
        Assert(other.SelectedCoSignOption is { CreateNew: true } && !other.SharedAddUnavailable,
            "switching the first file to create-new clears the fallback note");

        lead.SelectedCoSignOption = lead.CoSignOptions.First(option => !option.CreateNew);
        Assert(other.SharedAddUnavailable, "switching the first file back to add restores the note");

        vm.AddFiles(third);
        var added = vm.Files[2];
        Assert(!added.CoSignChoiceEnabled && added.SelectedCoSignOption is { CreateNew: false },
            "a newly added file with its own signature follows the first file's add mode");

        vm.ApplyCoSignToAll = false;
        Assert(added.CoSignChoiceEnabled && lead.SelectedCoSignOption is { CreateNew: false },
            "turning the checkbox off unlocks rows and keeps the current mode");
        added.SelectedCoSignOption = added.CoSignOptions.Single(option => option.CreateNew);
        Assert(lead.SelectedCoSignOption is { CreateNew: false } && added.SelectedCoSignOption is { CreateNew: true },
            "without the checkbox files choose independently");

        var saved = System.Text.Json.JsonSerializer.Deserialize<AppSettings>(
            await File.ReadAllTextAsync(Path.Combine(dir, "settings", "settings.json")));
        Assert(saved is { ApplyCoSignToAll: false }, "checkbox state must be saved");
        vm.ApplyCoSignToAll = true;
        saved = System.Text.Json.JsonSerializer.Deserialize<AppSettings>(
            await File.ReadAllTextAsync(Path.Combine(dir, "settings", "settings.json")));
        Assert(saved is { ApplyCoSignToAll: true }, "turning the checkbox on must be saved");
        Console.WriteLine("cosign: apply-to-all follows the first file and names a fallback: OK");
    }

    private static async Task CheckCreateNewConfirmation(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "create_new");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "заявка.pdf");
        var odd = Path.Combine(dir, "заявка-.pdf .sig");
        var canonical = document + ".sig";
        await File.WriteAllBytesAsync(document, data);
        var originalOdd = signer.Sign(data, certA);
        var originalCanonical = signer.Sign(data, certA);
        await File.WriteAllBytesAsync(odd, originalOdd);
        await File.WriteAllBytesAsync(canonical, originalCanonical);

        var vm = ViewModel(dir);
        vm.AddFiles(document);
        vm.MergeWithExisting = false;
        var item = vm.Files.Single();
        Assert(item.StatusDisplay.Contains("будет создан новый файл подписи")
            && item.StatusDisplay.Contains("будет заменён")
            && !item.StatusDisplay.Contains("резервн"),
            "create-new row must warn about replacement and not promise a backup while the setting is off: " + item.StatusDisplay);
        vm.CreateSignatureBackup = true;
        Assert(item.StatusDisplay.Contains("резервная копия"),
            "enabled backup must be mentioned in the plan: " + item.StatusDisplay);
        var risks = vm.DescribeSignRisks(vm.Files.ToList());
        Assert(risks is not null && risks.Contains("заявка-.pdf .sig") && risks.Contains("перезаписан без объединения"),
            "confirmation must mention the matching signature and the overwrite: " + risks);

        vm.SelectedCertificate = new CertificateItem(certB);
        vm.RequestConfirmAsync = (_, _) => Task.FromResult(false);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Pending, "declined confirmation must leave the file unsigned");
        Assert((await File.ReadAllBytesAsync(odd)).SequenceEqual(originalOdd), "declined sign must not touch the odd signature");
        Assert((await File.ReadAllBytesAsync(canonical)).SequenceEqual(originalCanonical), "declined sign must not overwrite canonical .sig");

        vm.RequestConfirmAsync = (_, _) => Task.FromResult(true);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed && item.StatusDisplay.StartsWith("Подписан: 1, новый файл", StringComparison.Ordinal),
            "confirmed create-new must say so: " + item.StatusDisplay);
        Assert((await File.ReadAllBytesAsync(odd)).SequenceEqual(originalOdd), "create-new must leave the other signature untouched");
        Assert(CmsMerger.CountSigners(await File.ReadAllBytesAsync(canonical)) == 1, "overwritten canonical file has only the new signer");
        var backup = Directory.GetFiles(dir, "заявка.pdf.sig.*.bak").Single();
        Assert((await File.ReadAllBytesAsync(backup)).SequenceEqual(originalCanonical), "overwrite keeps a backup of the previous .sig");
        Console.WriteLine("cosign: create-new asks before ignoring a match and before overwrite; backup kept: OK");
    }

    private static async Task CheckExclusionConfirmation(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, X509Certificate2 certC, byte[] data, byte[] other)
    {
        var dir = Path.Combine(root, "exclude");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "смета.pdf");
        var odd = Path.Combine(dir, "смета-.pdf .sig");
        await File.WriteAllBytesAsync(document, data);
        var mixed = CmsMerger.Merge(new[] { signer.Sign(data, certA), signer.Sign(other, certB) });
        await File.WriteAllBytesAsync(odd, mixed);

        var vm = ViewModel(dir);
        vm.AddFiles(document);
        var item = vm.Files.Single();
        Assert(item.HasWarning && item.WarningDisplay!.Contains("Перед исключением"),
            "row must warn before signers would be dropped: " + item.WarningDisplay);
        var risks = vm.DescribeSignRisks(vm.Files.ToList());
        Assert(risks is not null && risks.Contains("исключены подписанты") && risks.Contains("Подписант Б"),
            "confirmation must name the signer that would be dropped: " + risks);

        vm.SelectedCertificate = new CertificateItem(certC);
        vm.RequestConfirmAsync = (_, _) => Task.FromResult(false);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert((await File.ReadAllBytesAsync(odd)).SequenceEqual(mixed), "declined exclusion must keep the original signature");

        vm.RequestConfirmAsync = (_, _) => Task.FromResult(true);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed, "sign after confirmed exclusion failed: " + item.Message);
        Assert(item.HasWarning && item.WarningDisplay!.StartsWith("Внимание: исключены подписанты", StringComparison.Ordinal)
            && item.WarningDisplay.Contains("Подписант Б"),
            "excluded signer must stay visible after signing: " + item.WarningDisplay);
        var result = SignatureVerifier.Verify(await File.ReadAllBytesAsync(odd), data, Crypto);
        Assert(result.Signers.Count == 2 && result.Signers.All(s => s.CryptographicallyValid),
            "kept signers must verify; dropped signer must be gone");
        Console.WriteLine("cosign: exclusion needs confirmation and stays a warning on the row: OK");
    }

    private static async Task CheckUnmatchedSignatureListed(string root, DocumentSigner signer,
        X509Certificate2 certA, byte[] data, byte[] other)
    {
        var dir = Path.Combine(root, "unmatched");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "письмо.txt");
        await File.WriteAllBytesAsync(document, data);
        var foreign = Path.Combine(dir, "чужая подпись.sig");
        await File.WriteAllBytesAsync(foreign, signer.Sign(other, certA));
        var garbage = Path.Combine(dir, "битая.p7s");
        await File.WriteAllBytesAsync(garbage, new byte[] { 1, 2, 3, 4 });

        var vm = ViewModel(dir);
        vm.AddFiles(document, foreign, garbage);
        Assert(vm.Files.Count == 1, "signature files must not become documents in the queue");
        Assert(vm.StatusText.Contains("«чужая подпись.sig»") && vm.StatusText.Contains("«битая.p7s»")
            && vm.StatusText.Contains("не сопоставлены"),
            "unmatched signatures must be listed, not silently skipped: " + vm.StatusText);
        Assert(!vm.Files[0].StatusDisplay.Contains("чужая"), "foreign signature must not be attached: " + vm.Files[0].StatusDisplay);

        vm.AddFiles(Path.Combine(dir, "письмо-.txt .sig"));
        await File.WriteAllBytesAsync(Path.Combine(dir, "письмо-.txt .sig"), signer.Sign(data, certA));
        vm.AddFiles(Path.Combine(dir, "письмо-.txt .sig"));
        Assert(vm.Files[0].StatusDisplay.Contains("будет добавлена подпись №2")
            && vm.Files[0].StatusDisplay.Contains("письмо-.txt .sig"),
            "a signature dropped later must attach by hash: " + vm.Files[0].StatusDisplay);
        Console.WriteLine("cosign: unmatched .sig/.p7s are listed; a later drop still matches by hash: OK");
    }

    private static void CheckMergeNamesOutput(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "merge_name");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "акт.pdf");
        File.WriteAllBytes(document, data);
        var odd = Path.Combine(dir, "акт-.pdf .sig");
        var second = Path.Combine(dir, "вторая.p7s");
        File.WriteAllBytes(odd, signer.Sign(data, certA));
        File.WriteAllBytes(second, signer.Sign(data, certB));
        var canonical = document + ".sig";
        File.WriteAllBytes(canonical, new byte[] { 9, 9, 9 });

        var merged = CmsExtractor.MergeSignatureFiles(new[] { odd, second });
        Assert(Path.GetFileName(merged.OutputPath) == "акт.pdf (1).sig",
            "taken canonical name must get a unique suffix, not the odd input name: " + merged.OutputPath);
        Assert(File.ReadAllBytes(canonical).SequenceEqual(new byte[] { 9, 9, 9 }), "existing акт.pdf.sig must stay untouched");
        Assert(merged.DocumentNote.Contains("акт.pdf") && merged.DocumentNote.Contains("не перезаписан"),
            "note must say the document was found and the existing file was kept: " + merged.DocumentNote);
        Assert(CmsMerger.CountSigners(File.ReadAllBytes(merged.OutputPath)) == 2, "merged file keeps both signers");

        File.Delete(canonical);
        var cleanDir = Path.Combine(dir, "clean");
        Directory.CreateDirectory(cleanDir);
        var cleanDoc = Path.Combine(cleanDir, "акт.pdf");
        File.WriteAllBytes(cleanDoc, data);
        var cleanOdd = Path.Combine(cleanDir, "акт-.pdf .sig");
        File.WriteAllBytes(cleanOdd, signer.Sign(data, certA));
        File.WriteAllBytes(Path.Combine(cleanDir, "вторая.p7s"), signer.Sign(data, certB));
        var named = CmsExtractor.MergeSignatureFiles(new[] { cleanOdd, Path.Combine(cleanDir, "вторая.p7s") });
        Assert(Path.GetFileName(named.OutputPath) == "акт.pdf.sig",
            "when the document is known and имя.sig is free, that is the output: " + named.OutputPath);
        Console.WriteLine("cosign: merge output is «документ.sig» and does not clobber an existing file: OK");
    }

    private static void CheckGostParameters()
    {
        var curveOid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
        var digestOid = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
        var curve = ECGost3410NamedCurves.GetByOid(curveOid);
        var parameters = new ECGost3410Parameters(new ECNamedDomainParameters(curveOid, curve), curveOid, digestOid, null);
        var generator = new ECKeyPairGenerator("ECGOST3410");
        generator.Init(new ECKeyGenerationParameters(parameters, new SecureRandom()));
        var pair = generator.GenerateKeyPair();
        var other = generator.GenerateKeyPair();
        const string algorithm = "GOST3411-2012-256WITHECGOST3410-2012-256";
        var data = System.Text.Encoding.UTF8.GetBytes("ГОСТ с параметрами signatureAlgorithm");
        var cert = GostCert("GOST signer", pair, pair, algorithm);
        var encoded = GostSign(data, cert, pair, algorithm);
        var withParameters = WithCryptoProParameters(encoded);
        Assert(SignatureVerifier.Verify(encoded, data, Crypto).CryptographicallyValid, "GOST without parameters still verifies");
        var parameterized = SignatureVerifier.Verify(withParameters, data, Crypto);
        Assert(parameterized.CryptographicallyValid
            && parameterized.Signers[0].Signature.State == VerificationState.Valid
            && parameterized.Signers[0].Document.State == VerificationState.Valid,
            "CryptoPro-style signatureAlgorithm parameters must verify: " + parameterized.Signers[0].Signature.Message);

        var damaged = withParameters.ToArray();
        var signature = new CmsSignedData(withParameters).GetSignerInfos().GetSigners().First().GetSignature();
        var offset = damaged.AsSpan().IndexOf(signature);
        damaged[offset + signature.Length - 1] ^= 1;
        var broken = SignatureVerifier.Verify(damaged, data, Crypto).Signers.Single();
        Assert(broken.Signature.State == VerificationState.Invalid, "damaged GOST value must be invalid, not unknown: " + broken.Signature.Message);

        var second = GostCert("GOST other", other, other, algorithm);
        var merged = CmsMerger.MergeForDocument(new[] { withParameters, GostSign(data, second, other, algorithm) }, data);
        var values = SignatureValues(withParameters);
        var mergedValues = SignatureValues(merged.Signature);
        Assert(values.All(value => mergedValues.Any(item => item.SequenceEqual(value))),
            "merge must keep the original GOST signature bytes");
        Assert(SignatureVerifier.Verify(merged.Signature, data, Crypto).Signers.All(s => s.CryptographicallyValid),
            "both GOST signers verify after merge");
        Console.WriteLine("cosign: GOST signatureAlgorithm parameters verify; damaged value rejected; signer bytes kept: OK");
    }

    private static async Task CheckSamplesIfPresent(string root)
    {
        var zip = new[]
        {
            Environment.GetEnvironmentVariable("SIGNSERVICE_SAMPLES"),
            "/home/ubuntu/.cursor/projects/workspace/uploads/samples_8b69.zip",
        }.FirstOrDefault(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path!));
        if (zip is null)
        {
            Console.WriteLine("cosign: real samples not present, synthetic GOST parameters covered the verifier");
            return;
        }

        var dir = Path.Combine(root, "samples");
        Directory.CreateDirectory(dir);
        ZipFile.ExtractToDirectory(zip, dir, overwriteFiles: true);
        var pdf = Directory.GetFiles(dir, "*.pdf").Single(path => !path.EndsWith(".sig", StringComparison.OrdinalIgnoreCase));
        var signatures = Directory.GetFiles(dir, "*.sig");
        var eight = signatures.Single(path => CmsMerger.CountSigners(File.ReadAllBytes(path)) == 8);
        var one = signatures.Single(path => CmsMerger.CountSigners(File.ReadAllBytes(path)) == 1);
        var document = await File.ReadAllBytesAsync(pdf);
        var oldSignature = await File.ReadAllBytesAsync(eight);
        var newSignature = await File.ReadAllBytesAsync(one);
        var oldValues = SignatureValues(oldSignature);

        var oldCheck = SignatureVerifier.Verify(oldSignature, document, Crypto);
        Assert(oldCheck.Signers.Count == 8 && oldCheck.Signers.All(s => s.CryptographicallyValid),
            "sample 8 signers: " + string.Join(" | ", oldCheck.Signers.Select(s => s.Signature.State + " " + s.Document.State + " " + s.CertificateBinding.State)));

        var merged = CmsMerger.MergeForDocument(new[] { oldSignature, newSignature }, document, attach: false);
        var mergedValues = SignatureValues(merged.Signature);
        var preserved = oldValues.Count(value => mergedValues.Any(item => item.SequenceEqual(value)));
        var check = SignatureVerifier.Verify(merged.Signature, document, Crypto);
        Assert(merged.SignerCount == 9 && check.Signers.Count == 9 && check.Signers.All(s => s.CryptographicallyValid),
            "sample merge 9 signers: " + string.Join(" | ", check.Signers.Select(s =>
                $"{s.Number}:{s.Signature.State}/{s.Document.State}/{s.CertificateBinding.State} {s.Signature.Message}")));
        Assert(preserved == 8, $"original signature values preserved {preserved}/8");

        // В папке образца лежит и ошибочный одноподписный файл — он тоже совпадает по хешу.
        // Сценарий пользователя: только групповая подпись с нестандартным именем.
        var clean = Path.Combine(dir, "only_group");
        Directory.CreateDirectory(clean);
        var cleanPdf = Path.Combine(clean, Path.GetFileName(pdf));
        var cleanSig = Path.Combine(clean, Path.GetFileName(eight));
        await File.WriteAllBytesAsync(cleanPdf, document);
        await File.WriteAllBytesAsync(cleanSig, oldSignature);
        var vm = ViewModel(clean);
        vm.AddFiles(cleanPdf);
        var plan = vm.Files.Single().StatusDisplay;
        Assert(plan.Contains("будет добавлена подпись №9") && plan.Contains("8 подписантов")
            && plan.Contains(Path.GetFileName(eight)),
            "queue must offer to append signer 9 to the 8-signer file: " + plan);
        Console.WriteLine($"cosign samples: signers=9 allValid=true originalSignatureValuesPreserved={preserved}/8 plan={plan}");
    }

    private static MainWindowViewModel ViewModel(string dir)
    {
        var settings = new AppSettings(Path.Combine(dir, "settings")) { CheckUpdatesOnStart = false };
        return new MainWindowViewModel(new CertificateProvider(), new DocumentSigner(), settings,
            new CertificateVault(Path.Combine(dir, "vault")));
    }

    private static X509Certificate2 MakeCert(string subject)
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
    }

    private static BcCertificate GostCert(string name, AsymmetricCipherKeyPair key, AsymmetricCipherKeyPair issuerKey, string algorithm)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(name.GetHashCode() & 0x7fffffff));
        generator.SetSubjectDN(new X509Name("CN=" + name));
        generator.SetIssuerDN(new X509Name("CN=" + name));
        generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        generator.SetPublicKey(key.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
        return generator.Generate(new Asn1SignatureFactory(algorithm, issuerKey.Private));
    }

    private static byte[] GostSign(byte[] data, BcCertificate cert, AsymmetricCipherKeyPair key, string algorithm)
    {
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder()
            .Build(new Asn1SignatureFactory(algorithm, key.Private), cert));
        generator.AddCertificates(Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore(new[] { cert }));
        return generator.Generate(new CmsProcessableByteArray(data), encapsulate: false).GetEncoded();
    }

    /// <summary>Как КриптоПро: в signatureAlgorithm — SEQUENCE из OID набора параметров и OID хеша.</summary>
    private static byte[] WithCryptoProParameters(byte[] encoded)
    {
        var content = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(encoded));
        var signed = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(content.Content);
        var signerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo.GetInstance(signed.SignerInfos[0]);
        var parameters = new DerSequence(
            new DerObjectIdentifier("1.2.643.2.2.36.0"),
            new DerObjectIdentifier("1.2.643.7.1.1.2.2"));
        var changed = new Org.BouncyCastle.Asn1.Cms.SignerInfo(
            signerInfo.SignerID, signerInfo.DigestAlgorithm, signerInfo.SignedAttrs,
            new AlgorithmIdentifier(signerInfo.SignatureAlgorithm.Algorithm, parameters),
            signerInfo.Signature, signerInfo.UnsignedAttrs);
        return new Org.BouncyCastle.Asn1.Cms.ContentInfo(content.ContentType, new Org.BouncyCastle.Asn1.Cms.SignedData(
            signed.DigestAlgorithms, signed.EncapContentInfo, signed.Certificates, signed.CRLs,
            new DerSet(changed))).GetEncoded();
    }

    private static List<byte[]> SignatureValues(byte[] signature) =>
        new CmsSignedData(signature).GetSignerInfos().GetSigners().Select(signer => signer.GetSignature()).ToList();

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new Exception("cosign: " + message);
    }
}
