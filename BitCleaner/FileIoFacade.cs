using System;
using System.IO;
using System.Security.Cryptography;

namespace BitCleaner
{
    public class FileIoFacade
    {
        public string[] GetFiles(string directory, string pattern, EnumerationOptions enumerationOptions)
        {
            return Directory.GetFiles(directory, pattern, enumerationOptions);
        }

        public bool IsDirectory(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.Directory) == FileAttributes.Directory;
        }

        public bool IsHidden(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.Hidden) == FileAttributes.Hidden;
        }

        public bool IsSystem(string path)
        {
            return (File.GetAttributes(path) & FileAttributes.System) == FileAttributes.System;
        }

        public long ByteSize(string path)
        {
            return new FileInfo(path).Length;
        }

        public string Digest(string path, HashAlgorithmName digestAlgorithm)
        {
            var algo = HashAlgorithm.Create(digestAlgorithm.Name ?? "SHA1");
            using (var stream = new FileInfo(path).OpenRead())
            {
                var bytes = algo!.ComputeHash(stream);
                return Convert.ToHexString(bytes);
            }
        }
    }
}