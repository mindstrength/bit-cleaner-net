using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace BitCleaner
{
    public interface ScanStrategy<K> where K : notnull
    {
        Dictionary<K, List<string>> Scan();

        IEnumerable<string> Filter(IEnumerable<string> paths);
    }

    public abstract class AbstractScanStrategy<K> : ScanStrategy<K> where K : notnull
    {
		public AbstractScanStrategy(Options options, FileIoFacade fileIoFacade)
		{
			Options = options;
			FileIoFacade = fileIoFacade;
		}

        public Options Options { get; private set; }

        public FileIoFacade FileIoFacade { get; private set; }

        public Dictionary<K, List<string>> Scan()
        {
            var enumerationOptions = new EnumerationOptions();
            enumerationOptions.RecurseSubdirectories = true;
            enumerationOptions.AttributesToSkip = FileAttributes.Directory;
            if (!Options.IsIncludeHiddenFiles) enumerationOptions.AttributesToSkip |= FileAttributes.Hidden;
            if (!Options.IsIncludeSystemFiles) enumerationOptions.AttributesToSkip |= FileAttributes.System;

            var sourceFiles = GroupPaths(FileIoFacade.GetFiles(Options.SourceDirectory, "*", enumerationOptions));

            if (Options.TargetDirectory is not null && !Options.SourceDirectory.Equals(Options.TargetDirectory))
            {
                var targetFiles = GroupPaths(FileIoFacade.GetFiles(Options.TargetDirectory, "*", enumerationOptions));
                foreach (var key in sourceFiles.Keys.Intersect(targetFiles.Keys))
                {
                    sourceFiles[key].AddRange(targetFiles[key]);
                }
            }

            return sourceFiles;
        }

        public IEnumerable<string> Filter(IEnumerable<string> paths)
        {
            return GroupPaths(paths).SelectMany(group => group.Value);
        }

        private Dictionary<K, List<string>> GroupPaths(IEnumerable<string> paths)
        {
            if (Options.MinimumByteSize.HasValue)
            {
                paths = paths.Where(path => FileIoFacade.ByteSize(path) >= Options.MinimumByteSize.Value);
            }
            if (Options.NamePatterns is not null && Options.NamePatterns.Count > 0)
            {
                paths = paths.Where(
					path => Options.NamePatterns.Any(
                    	pattern => pattern.IsMatch(Path.GetFileName(path))
					)
                );
            }
            var groups = paths.GroupBy(p => KeyFunc(p))
                .Where(g => g.Count() > 1);
            return groups.ToDictionary(g => g.Key, g => g.ToList());
        }

        protected abstract K KeyFunc(string path);
    }

    public class FileDigest : AbstractScanStrategy<string>
    {
		public HashAlgorithmName DigestAlgorithm { get; private set; }

		public FileDigest(Options options, FileIoFacade fileIoFacade, HashAlgorithmName digestAlgorithm)
        : base(options, fileIoFacade)
		{
			DigestAlgorithm = digestAlgorithm;
		}

        protected override string KeyFunc(string path)
        {
			return FileIoFacade.Digest(path, DigestAlgorithm);
        }
    }

    public class FileName : AbstractScanStrategy<string>
    {
		public FileName(Options options, FileIoFacade fileIoFacade) : base(options, fileIoFacade)
		{

		}

        protected override string KeyFunc(string path)
        {
			var fileName = Path.GetFileName(path);
			if (Options.IsCaseInsensitive) fileName = fileName.ToLowerInvariant();
            return fileName;
        }
    }

    public record class Options
    {
        public string SourceDirectory { get; init; } = String.Empty;
        public string? TargetDirectory { get; init; }
        public ISet<Regex> NamePatterns { get; init; } = new HashSet<Regex>();
        public bool IsCaseInsensitive { get; init; }
        public bool IsIncludeHiddenFiles { get; init; }
        public bool IsIncludeSystemFiles { get; init; }
        public long? MinimumByteSize { get; init; }
    }

    public class StrategyFactory
    {
        public ScanStrategy<string> Create(CommonStrategy strategy, Options options, FileIoFacade fileIoFacade)
        {
            switch (strategy)
			{
				case CommonStrategy.FileName: return new FileName(options, fileIoFacade);
				case CommonStrategy.FileDigest: return new FileDigest(options, fileIoFacade, HashAlgorithmName.SHA1);
				default: throw new ArgumentException($"{strategy} is not registered in the StrategyFactory.");
			}
        }
    }

	public enum CommonStrategy
	{
		FileName,
		FileDigest
	}
}
