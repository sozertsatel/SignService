using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;

namespace SignService.Services;

/// <summary>
/// Поиск существующих откреплённых подписей документа по хешу содержимого,
/// а не по имени файла: «документ-.pdf .sig» рядом с «документ.pdf» тоже находится.
/// </summary>
public static class SignatureDiscovery
{
    public const long MaxDocumentBytes = 200L * 1024 * 1024;

    /// <summary>Файл подписи и то, сколько его подписантов совпали с документом по messageDigest.</summary>
    public sealed record SignatureMatch(
        string Path,
        int SignerCount,
        int MatchingSigners,
        IReadOnlyList<string> MismatchedSignerNames);

    public static bool IsSignatureFile(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".sig", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".p7s", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".p7m", StringComparison.OrdinalIgnoreCase);
    }

    public static bool SamePath(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);

    /// <summary>«имя.sig» / «имя.p7s» → «имя». Для файла без расширения подписи — null.</summary>
    public static string? SiblingDocumentPath(string signaturePath) =>
        IsSignatureFile(signaturePath) ? signaturePath[..^Path.GetExtension(signaturePath).Length] : null;

    /// <summary>Склонение: 1 подписант, 2 подписанта, 8 подписантов.</summary>
    public static string SignerWord(int count)
    {
        var hundred = count % 100;
        var ten = count % 10;
        if (hundred is >= 11 and <= 14)
            return "подписантов";
        if (ten == 1)
            return "подписант";
        if (ten is >= 2 and <= 4)
            return "подписанта";
        return "подписантов";
    }

    /// <summary>
    /// Подписи .sig/.p7s/.p7m в каталоге документа, у которых хотя бы один
    /// подписант совпал по хешу. Имя файла не учитывается.
    /// </summary>
    public static IReadOnlyList<SignatureMatch> FindForDocument(string documentPath)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(documentPath));
        if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory))
            return Array.Empty<SignatureMatch>();

        byte[] document;
        try
        {
            document = File.ReadAllBytes(documentPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return Array.Empty<SignatureMatch>();
        }

        var digests = new DocumentDigests(document);
        var found = new List<SignatureMatch>();
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            if (!IsSignatureFile(file) || SamePath(file, documentPath))
                continue;
            var match = Match(file, digests);
            if (match is { MatchingSigners: > 0 })
                found.Add(match);
        }

        return found
            .OrderByDescending(m => m.MatchingSigners)
            .ThenByDescending(m => m.SignerCount)
            .ThenByDescending(m => SamePath(m.Path, documentPath + ".sig"))
            .ThenBy(m => m.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Совпадает ли конкретный файл подписи с документом. null — файл не разобрать.</summary>
    public static SignatureMatch? MatchToDocument(string signaturePath, string documentPath)
    {
        try
        {
            return Match(signaturePath, new DocumentDigests(File.ReadAllBytes(documentPath)));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Документ в каталоге, хеш которого совпал с messageDigest подписей.
    /// Нужен, когда имя .sig не равно «документ.sig».
    /// </summary>
    public static string? FindDocumentByContent(string directory, IReadOnlyList<string> signaturePaths)
    {
        var needed = new List<(string Oid, byte[] Digest)>();
        foreach (var path in signaturePaths)
        {
            try
            {
                var cms = new CmsSignedData(CmsMerger.Normalize(File.ReadAllBytes(path)));
                foreach (SignerInformation signer in cms.GetSignerInfos().GetSigners())
                {
                    if (!TryGetMessageDigest(signer, out var digest))
                        continue;
                    var oid = signer.DigestAlgorithmID.Algorithm.Id;
                    if (needed.Any(item => item.Oid == oid && item.Digest.AsSpan().SequenceEqual(digest)))
                        continue;
                    needed.Add((oid, digest));
                }
            }
            catch (Exception)
            {
            }
        }

        if (needed.Count == 0 || !Directory.Exists(directory))
            return null;

        string? best = null;
        var bestScore = 0;
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            if (IsSignatureFile(file) || signaturePaths.Any(path => SamePath(path, file)))
                continue;
            var info = new FileInfo(file);
            if (!info.Exists || info.Length == 0 || info.Length > MaxDocumentBytes)
                continue;

            byte[] content;
            try
            {
                content = File.ReadAllBytes(file);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            var digests = new DocumentDigests(content);
            var score = 0;
            foreach (var (oid, digest) in needed)
            {
                var actual = digests.Get(oid);
                if (actual is not null && actual.AsSpan().SequenceEqual(digest))
                    score++;
            }

            if (score > bestScore)
            {
                bestScore = score;
                best = file;
            }
        }

        return best;
    }

    private static SignatureMatch? Match(string signaturePath, DocumentDigests digests)
    {
        byte[] raw;
        try
        {
            raw = File.ReadAllBytes(signaturePath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        CmsSignedData cms;
        try
        {
            cms = new CmsSignedData(CmsMerger.Normalize(raw));
        }
        catch (Exception)
        {
            return null;
        }

        var signers = cms.GetSignerInfos().GetSigners().ToList();
        if (signers.Count == 0)
            return null;

        IReadOnlyList<string> names;
        try
        {
            names = CmsMerger.GetSigners(raw).Select(signer => signer.Name).ToList();
        }
        catch (Exception)
        {
            names = Array.Empty<string>();
        }

        var matching = 0;
        var mismatched = new List<string>();
        for (var i = 0; i < signers.Count; i++)
        {
            var name = i < names.Count ? names[i] : "неизвестный подписант";
            if (DigestMatches(signers[i], digests))
                matching++;
            else
                mismatched.Add(name);
        }

        return new SignatureMatch(signaturePath, signers.Count, matching, mismatched);
    }

    private static bool DigestMatches(SignerInformation signer, DocumentDigests digests)
    {
        if (!TryGetMessageDigest(signer, out var digest))
            return false;
        var actual = digests.Get(signer.DigestAlgorithmID.Algorithm.Id);
        return actual is not null && actual.AsSpan().SequenceEqual(digest);
    }

    private static bool TryGetMessageDigest(SignerInformation signer, out byte[] digest)
    {
        digest = Array.Empty<byte>();
        try
        {
            var attribute = signer.SignedAttributes?[PkcsObjectIdentifiers.Pkcs9AtMessageDigest];
            if (attribute is null || attribute.AttrValues.Count != 1)
                return false;
            digest = Asn1OctetString.GetInstance(attribute.AttrValues[0]).GetOctets();
            return digest.Length > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
