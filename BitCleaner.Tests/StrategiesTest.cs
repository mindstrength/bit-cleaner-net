using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Moq;
using Xunit;

namespace BitCleaner.Tests
{
    /// <summary>Unit tests for <c cref="FileDigest">FileDigest</c>.</summary>
    public class FileDigestTest
    {
        Mock<FileIoFacade> fileIoFacadeMock;
        ScanStrategy<string> fileDigest;

        public FileDigestTest()
        {
            fileIoFacadeMock = new Mock<FileIoFacade>();
            fileDigest = new FileDigest(new Options(), fileIoFacadeMock.Object, HashAlgorithmName.SHA1);
        }
        
        [Fact]
        public void Scan_Empty()
        {
            var result = fileDigest.Scan();
            Assert.Empty(result);
        }

        [Fact]
        public void Scan_GroupedByDigest()
        {
            var options = new Options()
            {
                SourceDirectory = "source"
            };

            fileIoFacadeMock.Setup(f => f.GetFiles("source", It.IsAny<string>(), It.IsAny<EnumerationOptions>()))
                .Returns(new string[] {
                    "source/a.mp3",
                    "source/b.mp3",
                    "source/sub/a_copy.mp3",
                    "source/sub/b_copy.mp3"
                });
            fileIoFacadeMock.Setup(f => f.Digest(It.Is<string>(s => s.Contains("/a")), It.IsAny<HashAlgorithmName>()))
                .Returns("a-digest");
            fileIoFacadeMock.Setup(f => f.Digest(It.Is<string>(s => s.Contains("/b")), It.IsAny<HashAlgorithmName>()))
                .Returns("b-digest");
            
            fileDigest = new FileDigest(options, fileIoFacadeMock.Object, HashAlgorithmName.SHA1);

            var result = fileDigest.Scan();

            Assert.True(
                result
                .Where(entry => entry.Key == "a-digest")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/a.mp3",
                    "source/sub/a_copy.mp3"
                    }),
                "a-digest does not contain expected paths");
            Assert.True(
                result
                .Where(entry => entry.Key == "b-digest")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/b.mp3",
                    "source/sub/b_copy.mp3"
                    }),
                "b-digest does not contain expected paths");
        }

        [Fact]
        public void Scan_GroupedByDigest_AllOptions()
        {
            var options = new Options()
            {
                SourceDirectory = "source",
                TargetDirectory = "target",
                IsCaseInsensitive = true,
                IsIncludeHiddenFiles = true,
                IsIncludeSystemFiles = true,
                MinimumByteSize = 1024,
                NamePatterns = new HashSet<Regex>() { new Regex(@".+\.mp3", RegexOptions.IgnoreCase) }
            };

            fileIoFacadeMock.Setup(f => f.GetFiles("source", It.IsAny<string>(), It.IsAny<EnumerationOptions>()))
                .Returns(new string[] {
                    "source/a.mp3",
                    "source/a_small.mp3",
                    "source/a.txt",
                    "source/foo.txt",
                    "source/b.mp3",
                    "source/b_small.mp3",
                    "source/sub/a_copy.mp3",
                    "source/sub/b_copy.mp3"
                });
            fileIoFacadeMock.Setup(f => f.GetFiles("target", It.IsAny<string>(), It.IsAny<EnumerationOptions>()))
                .Returns(new string[] {
                    "target/a.mp3",
                    "target/b.mp3",
                    "target/sub/a_copy.mp3",
                    "target/sub/b_copy.mp3"
                });
            fileIoFacadeMock.Setup(f => f.ByteSize(It.Is<string>(s => s.Contains("small"))))
                .Returns(256);
            fileIoFacadeMock.Setup(f => f.ByteSize(It.Is<string>(s => !s.Contains("small"))))
                .Returns(1024);
            fileIoFacadeMock.Setup(f => f.IsHidden(It.IsAny<string>()))
                .Returns(true);
            fileIoFacadeMock.Setup(f => f.IsSystem(It.IsAny<string>()))
                .Returns(true);
            fileIoFacadeMock.Setup(f => f.Digest(It.Is<string>(s => s.Contains("/a")), It.IsAny<HashAlgorithmName>()))
                .Returns("a-digest");
            fileIoFacadeMock.Setup(f => f.Digest(It.Is<string>(s => s.Contains("/b")), It.IsAny<HashAlgorithmName>()))
                .Returns("b-digest");
            
            fileDigest = new FileDigest(options, fileIoFacadeMock.Object, HashAlgorithmName.SHA1);

            var result = fileDigest.Scan();

            Assert.True(
                result
                .Where(entry => entry.Key == "a-digest")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/a.mp3",
                    "source/sub/a_copy.mp3",
                    "target/a.mp3",
                    "target/sub/a_copy.mp3"
                    }),
                "a-digest does not contain expected paths");
            Assert.True(
                result
                .Where(entry => entry.Key == "b-digest")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/b.mp3",
                    "source/sub/b_copy.mp3",
                    "target/b.mp3",
                    "target/sub/b_copy.mp3"
                    }),
                "b-digest does not contain expected paths");
        }
    }

    /// <summary>Unit tests for <c cref="FileName">FileName</c>.</summary>
    public class FileNameTest
    {
        Mock<FileIoFacade> fileIoFacadeMock;
        ScanStrategy<string> fileName;

        public FileNameTest()
        {
            fileIoFacadeMock = new Mock<FileIoFacade>();
            fileName = new FileName(new Options(), fileIoFacadeMock.Object);
        }
        
        [Fact]
        public void Scan_Empty()
        {
            var result = fileName.Scan();
            Assert.Empty(result);
        }

        [Fact]
        public void Scan_GroupedByDigest()
        {
            var options = new Options()
            {
                SourceDirectory = "source"
            };

            fileIoFacadeMock.Setup(f => f.GetFiles("source", It.IsAny<string>(), It.IsAny<EnumerationOptions>()))
                .Returns(new string[] {
                    "source/a.mp3",
                    "source/b.mp3",
                    "source/sub/a.mp3",
                    "source/sub/b.mp3"
                });
            
            fileName = new FileName(options, fileIoFacadeMock.Object);

            var result = fileName.Scan();

            Assert.True(
                result
                .Where(entry => entry.Key == "a.mp3")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/a.mp3",
                    "source/sub/a.mp3"
                    }),
                "a.mp3 does not contain expected paths");
            Assert.True(
                result
                .Where(entry => entry.Key == "b.mp3")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/b.mp3",
                    "source/sub/b.mp3"
                    }),
                "b.mp3 does not contain expected paths");
        }

        [Fact]
        public void Scan_GroupedByDigest_AllOptions()
        {
            var options = new Options()
            {
                SourceDirectory = "source",
                TargetDirectory = "target",
                IsCaseInsensitive = true,
                IsIncludeHiddenFiles = true,
                IsIncludeSystemFiles = true,
                MinimumByteSize = 1024,
                NamePatterns = new HashSet<Regex>() { new Regex(@".+\.mp3", RegexOptions.IgnoreCase) }
            };

            fileIoFacadeMock.Setup(f => f.GetFiles("source", It.IsAny<string>(), It.IsAny<EnumerationOptions>()))
                .Returns(new string[] {
                    "source/a.mp3",
                    "source/small/a.mp3",
                    "source/a.txt",
                    "source/foo.txt",
                    "source/b.mp3",
                    "source/small/b.mp3",
                    "source/sub/a.mp3",
                    "source/sub/b.mp3"
                });
            fileIoFacadeMock.Setup(f => f.GetFiles("target", It.IsAny<string>(), It.IsAny<EnumerationOptions>()))
                .Returns(new string[] {
                    "target/a.mp3",
                    "target/b.mp3",
                    "target/sub/a.mp3",
                    "target/sub/b.mp3"
                });
            fileIoFacadeMock.Setup(f => f.ByteSize(It.Is<string>(s => s.Contains("small"))))
                .Returns(256);
            fileIoFacadeMock.Setup(f => f.ByteSize(It.Is<string>(s => !s.Contains("small"))))
                .Returns(1024);
            fileIoFacadeMock.Setup(f => f.IsHidden(It.IsAny<string>()))
                .Returns(true);
            fileIoFacadeMock.Setup(f => f.IsSystem(It.IsAny<string>()))
                .Returns(true);
            
            fileName = new FileName(options, fileIoFacadeMock.Object);

            var result = fileName.Scan();

            Assert.True(
                result
                .Where(entry => entry.Key == "a.mp3")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/a.mp3",
                    "source/sub/a.mp3",
                    "target/a.mp3",
                    "target/sub/a.mp3"
                    }),
                "a.mp3 does not contain expected paths");
            Assert.True(
                result
                .Where(entry => entry.Key == "b.mp3")
                .Select(entry => entry.Value)
                .FirstOrDefault(new List<string>())
                .SequenceEqual(new List<string>() {
                    "source/b.mp3",
                    "source/sub/b.mp3",
                    "target/b.mp3",
                    "target/sub/b.mp3"
                    }),
                "b.mp3 does not contain expected paths");
        }
    }
}